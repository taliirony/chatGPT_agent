// chatGPT_agent.cpp
// ChatGPT Data Loss Prevention Agent
// Monitors ChatGPT browser interactions for email in pasted text
// and Google Drive-sourced file uploads.
//
// Build: set PATH=C:\msys64\ucrt64\bin;%PATH%
//        g++ -std=c++17 -O2 -static -o chatGPT_agent.exe chatGPT_agent.cpp -lole32 -loleaut32 -lshell32 -lshlwapi -luser32 -luuid

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>    // HDROP, DragQueryFileW
#include <uiautomation.h>
#include <exdisp.h>      // IShellWindows, IWebBrowserApp
#include <servprov.h>    // IServiceProvider

#include <string>
#include <regex>
#include <fstream>
#include <mutex>
#include <vector>
#include <thread>
#include <atomic>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "user32.lib")

namespace fs = std::filesystem;

// ============================================================
// Logger – thread-safe append to log file
// ============================================================
class Logger {
public:
    explicit Logger(const std::string& path) : logPath_(path) {}

    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::ofstream ofs(logPath_, std::ios::app);
        if (!ofs.is_open()) return;

        auto now  = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm ti;
        localtime_s(&ti, &t);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &ti);

        ofs << "[" << ts << "] " << message << "\n";
    }

private:
    std::string  logPath_;
    std::mutex   mtx_;
};

// ============================================================
// Globals
// ============================================================
static Logger*            g_logger  = nullptr;
static std::atomic<bool>  g_running{true};

// Keyboard hook handle
static HHOOK g_keyboardHook = nullptr;
// Mouse hook handle
static HHOOK g_mouseHook    = nullptr;
// Hidden window handle (needed to open clipboard)
static HWND  g_hiddenWnd    = nullptr;

// Right-click context menu tracking
static std::atomic<bool>   g_contextMenuOpen{false};
static std::atomic<ULONGLONG> g_rightClickTime{0};

// Drag-and-drop polling detection
static const UINT_PTR  DRAG_POLL_TIMER_ID = 42;
static const UINT      DRAG_POLL_INTERVAL = 150;   // ms
static bool            g_dragBlocked = false;       // cooldown after blocking one drag
static HWND            g_dragSourceExplorerHwnd = nullptr;  // Explorer window where drag started

// ============================================================
// Utility helpers
// ============================================================

// Convert wide string to UTF-8
static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                        &s[0], len, nullptr, nullptr);
    return s;
}

// Case-insensitive wide-string toLower
static std::wstring toLowerW(std::wstring s) {
    for (auto& c : s) c = towlower(c);
    return s;
}

// Check the browser address bar for "chatgpt.com" via UI Automation.
// Works with Chrome, Edge, Firefox (they expose the URL bar as an
// editable or value-holding automation element).
static bool browserUrlContainsChatGPT(HWND hwnd) {
    // Lazy-init COM + UIAutomation on the main thread
    static IUIAutomation* pAuto = nullptr;
    static bool comInit = false;
    if (!comInit) {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        CoCreateInstance(__uuidof(CUIAutomation), nullptr,
                         CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation),
                         reinterpret_cast<void**>(&pAuto));
        comInit = true;
    }
    if (!pAuto || !hwnd) return false;

    IUIAutomationElement* pRoot = nullptr;
    if (FAILED(pAuto->ElementFromHandle(hwnd, &pRoot)) || !pRoot)
        return false;

    // Look for Edit controls (address bar)
    VARIANT var;
    var.vt  = VT_I4;
    var.lVal = UIA_EditControlTypeId;
    IUIAutomationCondition* pCond = nullptr;
    pAuto->CreatePropertyCondition(UIA_ControlTypePropertyId, var, &pCond);
    if (!pCond) { pRoot->Release(); return false; }

    IUIAutomationElementArray* pArr = nullptr;
    pRoot->FindAll(TreeScope_Descendants, pCond, &pArr);
    pCond->Release();

    bool found = false;
    if (pArr) {
        int cnt = 0;
        pArr->get_Length(&cnt);
        for (int i = 0; i < cnt && !found; ++i) {
            IUIAutomationElement* pEl = nullptr;
            pArr->GetElement(i, &pEl);
            if (!pEl) continue;

            // Check element name for "address" / "url" patterns
            BSTR name = nullptr;
            pEl->get_CurrentName(&name);
            bool isAddrBar = false;
            if (name) {
                std::wstring wn = toLowerW(name);
                SysFreeString(name);
                isAddrBar = wn.find(L"address") != std::wstring::npos ||
                            wn.find(L"url")     != std::wstring::npos;
            }

            if (isAddrBar) {
                // Try ValuePattern to get the URL
                IUIAutomationValuePattern* pVal = nullptr;
                HRESULT hr = pEl->GetCurrentPatternAs(
                    UIA_ValuePatternId,
                    __uuidof(IUIAutomationValuePattern),
                    reinterpret_cast<void**>(&pVal));
                if (SUCCEEDED(hr) && pVal) {
                    BSTR v = nullptr;
                    pVal->get_CurrentValue(&v);
                    if (v) {
                        std::wstring url = toLowerW(v);
                        SysFreeString(v);
                        if (url.find(L"chatgpt.com") != std::wstring::npos)
                            found = true;
                    }
                    pVal->Release();
                }
            }
            pEl->Release();
        }
        pArr->Release();
    }
    pRoot->Release();
    return found;
}

// Check whether the foreground window is a ChatGPT session.
// First checks the window title for "chatgpt", then falls back to
// reading the browser address bar URL for "chatgpt.com".
static bool isChatGPTForeground() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return false;

    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, _countof(title));
    std::wstring t = toLowerW(title);

    // Quick check: title contains "chatgpt"
    if (t.find(L"chatgpt") != std::wstring::npos)
        return true;

    // Fallback: check browser address bar for chatgpt.com
    // Only try this if the window looks like a browser
    if (t.find(L"chrome")  != std::wstring::npos ||
        t.find(L"edge")    != std::wstring::npos ||
        t.find(L"firefox") != std::wstring::npos ||
        t.find(L"brave")   != std::wstring::npos ||
        t.find(L"opera")   != std::wstring::npos) {
        return browserUrlContainsChatGPT(hwnd);
    }

    return false;
}

// Enumerate all top-level windows owned by a given process and
// return true if any of them has "chatgpt" in its title.
struct EnumChatGPTCtx { DWORD pid; bool found; };

static BOOL CALLBACK enumWndCb(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<EnumChatGPTCtx*>(lp);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid) return TRUE;          // not our process

    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, _countof(title));
    if (toLowerW(title).find(L"chatgpt") != std::wstring::npos) {
        ctx->found = true;
        return FALSE;                            // stop enumerating
    }
    return TRUE;
}

static bool processHasChatGPTWindow(DWORD pid) {
    EnumChatGPTCtx ctx{pid, false};
    EnumWindows(enumWndCb, reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

// Check if ANY visible browser window is showing ChatGPT.
// Checks both title and address bar URL.
static bool anyChatGPTWindowExists() {
    struct Ctx { bool found; };
    Ctx ctx{false};
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t title[512]{};
        GetWindowTextW(hwnd, title, _countof(title));
        std::wstring t = toLowerW(title);
        if (t.find(L"chatgpt") != std::wstring::npos) {
            c->found = true;
            return FALSE;
        }
        // Check browser URL if it looks like a browser window
        if (t.find(L"chrome")  != std::wstring::npos ||
            t.find(L"edge")    != std::wstring::npos ||
            t.find(L"firefox") != std::wstring::npos ||
            t.find(L"brave")   != std::wstring::npos ||
            t.find(L"opera")   != std::wstring::npos) {
            if (browserUrlContainsChatGPT(hwnd)) {
                c->found = true;
                return FALSE;
            }
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

// Regex-based email detection
static bool containsEmail(const std::string& text) {
    static const std::regex re(
        R"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})");
    return std::regex_search(text, re);
}

// Read the NTFS Zone.Identifier ADS and check for drive.google.com
static bool isFromGoogleDrive(const std::wstring& filePath) {
    std::wstring adsPath = filePath + L":Zone.Identifier";

    HANDLE hFile = CreateFileW(adsPath.c_str(), GENERIC_READ,
                               FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                               nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    char buf[4096]{};
    DWORD bytesRead = 0;
    ReadFile(hFile, buf, sizeof(buf) - 1, &bytesRead, nullptr);
    CloseHandle(hFile);

    std::string content(buf, bytesRead);
    // case-insensitive search
    std::string lower = content;
    for (auto& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    // Match both drive.google.com and drive.usercontent.google.com
    return lower.find("drive.google.com") != std::string::npos ||
           lower.find("drive.usercontent.google.com") != std::string::npos;
}

// Get the user's Downloads folder
static std::wstring getDownloadsFolder() {
    wchar_t* path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0,
                                       nullptr, &path))) {
        std::wstring result(path);
        CoTaskMemFree(path);
        return result;
    }
    return {};
}

// ============================================================
// Drag-and-drop helpers (poll-based)
// ============================================================

// Query Explorer windows for their currently selected files.
// If filterHwnd is non-null, only return files from the Explorer window
// whose top-level HWND matches filterHwnd.
static std::vector<std::wstring> getExplorerSelectedFiles(HWND filterHwnd = nullptr) {
    std::vector<std::wstring> result;

    IShellWindows* pShellWindows = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellWindows, nullptr,
                                  CLSCTX_ALL, IID_PPV_ARGS(&pShellWindows));
    if (FAILED(hr) || !pShellWindows) return result;

    long count = 0;
    pShellWindows->get_Count(&count);

    for (long i = 0; i < count; ++i) {
        VARIANT idx;
        idx.vt = VT_I4;
        idx.lVal = i;

        IDispatch* pDisp = nullptr;
        hr = pShellWindows->Item(idx, &pDisp);
        if (FAILED(hr) || !pDisp) continue;

        // If filtering by HWND, check this window's HWND via IWebBrowserApp
        if (filterHwnd) {
            IWebBrowserApp* pWBA = nullptr;
            hr = pDisp->QueryInterface(IID_PPV_ARGS(&pWBA));
            if (SUCCEEDED(hr) && pWBA) {
                SHANDLE_PTR hWndRaw = 0;
                pWBA->get_HWND(&hWndRaw);
                pWBA->Release();
                HWND thisHwnd = reinterpret_cast<HWND>(hWndRaw);
                if (thisHwnd != filterHwnd) {
                    pDisp->Release();
                    continue;
                }
            } else {
                pDisp->Release();
                continue;
            }
        }

        IServiceProvider* pSP = nullptr;
        hr = pDisp->QueryInterface(IID_PPV_ARGS(&pSP));
        pDisp->Release();
        if (FAILED(hr) || !pSP) continue;

        IShellBrowser* pSB = nullptr;
        hr = pSP->QueryService(SID_STopLevelBrowser, IID_PPV_ARGS(&pSB));
        pSP->Release();
        if (FAILED(hr) || !pSB) continue;

        IShellView* pSV = nullptr;
        hr = pSB->QueryActiveShellView(&pSV);
        pSB->Release();
        if (FAILED(hr) || !pSV) continue;

        IDataObject* pDataObj = nullptr;
        hr = pSV->GetItemObject(SVGIO_SELECTION, IID_PPV_ARGS(&pDataObj));
        pSV->Release();
        if (FAILED(hr) || !pDataObj) continue;

        FORMATETC fmt = { CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        STGMEDIUM stg = {};
        hr = pDataObj->GetData(&fmt, &stg);
        pDataObj->Release();
        if (FAILED(hr)) continue;

        HDROP hDrop = static_cast<HDROP>(GlobalLock(stg.hGlobal));
        if (hDrop) {
            UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0);
            for (UINT f = 0; f < fileCount; ++f) {
                wchar_t path[MAX_PATH]{};
                DragQueryFileW(hDrop, f, path, MAX_PATH);
                if (path[0]) result.emplace_back(path);
            }
            GlobalUnlock(stg.hGlobal);
        }
        ReleaseStgMedium(&stg);
    }

    pShellWindows->Release();
    return result;
}

// Check if a window belongs to Explorer (explorer.exe).
static bool isExplorerWindow(HWND hwnd) {
    if (!hwnd) return false;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) return false;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    wchar_t exePath[MAX_PATH]{};
    DWORD sz = MAX_PATH;
    bool isExplorer = false;
    if (QueryFullProcessImageNameW(hProc, 0, exePath, &sz)) {
        std::wstring name = toLowerW(exePath);
        isExplorer = name.find(L"explorer.exe") != std::wstring::npos;
    }
    CloseHandle(hProc);
    return isExplorer;
}

// Walk GetParent() to find the top-level window.
static HWND getTopLevelParent(HWND hwnd) {
    while (hwnd) {
        HWND parent = GetParent(hwnd);
        if (!parent) break;
        hwnd = parent;
    }
    return hwnd;
}

// Check whether a given top-level window is a ChatGPT session.
static bool isChatGPTWindow(HWND hwnd) {
    if (!hwnd || !IsWindowVisible(hwnd)) return false;

    wchar_t title[512]{};
    GetWindowTextW(hwnd, title, _countof(title));
    std::wstring t = toLowerW(title);

    if (t.find(L"chatgpt") != std::wstring::npos)
        return true;

    // Check browser URL if it looks like a browser window
    if (t.find(L"chrome")  != std::wstring::npos ||
        t.find(L"edge")    != std::wstring::npos ||
        t.find(L"firefox") != std::wstring::npos ||
        t.find(L"brave")   != std::wstring::npos ||
        t.find(L"opera")   != std::wstring::npos) {
        return browserUrlContainsChatGPT(hwnd);
    }
    return false;
}

// Poll-based drag detection: called every DRAG_POLL_INTERVAL ms.
// When left mouse button is first pressed over an Explorer window, we
// record that as the drag source. While dragging, if the cursor moves
// over a ChatGPT window, we query ONLY the source Explorer window's
// selection for Google Drive files.
static void onDragPollTimer() {
    bool lButtonDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;

    if (!lButtonDown) {
        // Mouse released — reset state
        g_dragBlocked = false;
        g_dragSourceExplorerHwnd = nullptr;
        return;
    }

    // Already blocked this drag gesture — wait for mouse release
    if (g_dragBlocked) return;

    // If we haven't identified a drag source yet, check if cursor is
    // currently over an Explorer window (this captures the start of drag)
    if (!g_dragSourceExplorerHwnd) {
        POINT pt;
        GetCursorPos(&pt);
        HWND hwndUnder = WindowFromPoint(pt);
        if (!hwndUnder) return;
        HWND topLevel = getTopLevelParent(hwndUnder);
        if (isExplorerWindow(topLevel)) {
            g_dragSourceExplorerHwnd = topLevel;
        }
        return;  // don't check on the same tick we identify the source
    }

    // We have a drag source Explorer window — check if cursor is now
    // over a ChatGPT window
    POINT pt;
    GetCursorPos(&pt);
    HWND hwndUnder = WindowFromPoint(pt);
    if (!hwndUnder) return;
    HWND topLevel = getTopLevelParent(hwndUnder);
    if (!isChatGPTWindow(topLevel)) return;

    // Cursor is over ChatGPT while dragging from Explorer —
    // query ONLY the source Explorer window's selection
    auto files = getExplorerSelectedFiles(g_dragSourceExplorerHwnd);
    if (files.empty()) return;

    // Debug: log all files returned by Explorer selection query
    g_logger->log("Debug: Drag poll - Explorer selection has " +
                  std::to_string(files.size()) + " file(s):");
    for (const auto& fp : files) {
        bool ads = isFromGoogleDrive(fp);
        g_logger->log("Debug:   " + wideToUtf8(fp) +
                      " ads=" + (ads ? "Y" : "N"));
    }

    bool hasDrive = false;
    std::string driveFile;
    for (const auto& fp : files) {
        if (isFromGoogleDrive(fp)) {
            hasDrive = true;
            driveFile = wideToUtf8(fp);
            break;
        }
    }
    if (!hasDrive) return;

    // Block: simulate Escape to cancel drag
    INPUT inputs[2] = {};
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_ESCAPE;
    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = VK_ESCAPE;
    inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, inputs, sizeof(INPUT));

    g_dragBlocked = true;

    g_logger->log("Alert: Drive-sourced file drag-drop to ChatGPT blocked. file="
                  + driveFile);

    MessageBoxW(nullptr,
        L"Upload blocked: the dragged file originated from "
        L"Google Drive and cannot be dropped into ChatGPT.",
        L"ChatGPT Agent",
        MB_OK | MB_ICONWARNING);
}

// ============================================================
// Paste monitor — two mechanisms:
//
//   1) Low-level keyboard hook (Ctrl+V / Ctrl+Shift+V)
//      Fires on every paste keystroke.
//
//   2) Low-level mouse hook (right-click > Paste)
//      Detects right-click followed by left-click (menu selection)
//      while ChatGPT is in the foreground.
//
//   Both read the clipboard directly at paste time.
// ============================================================

// Read clipboard text and check for email addresses
static void checkClipboardForEmail() {
    if (!OpenClipboard(g_hiddenWnd)) return;
    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        const wchar_t* p =
            static_cast<const wchar_t*>(GlobalLock(hData));
        if (p) {
            std::string utf8 = wideToUtf8(p);
            GlobalUnlock(hData);
            // Log first 100 chars of clipboard for debugging
            std::string preview = utf8.substr(0, 100);
            g_logger->log("Debug: Clipboard text (first 100): " + preview);
            if (containsEmail(utf8)) {
                g_logger->log(
                    "Alert: Email detected from ChatGPT upload.");
            }
        }
    }
    CloseClipboard();
}

// Mechanism 1: keyboard hook — catches every Ctrl+V
static LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wp, LPARAM lp) {
    if (nCode == HC_ACTION && wp == WM_KEYDOWN) {
        auto* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
        if (kb->vkCode == 'V' &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            bool chatgpt = isChatGPTForeground();
            HWND fg = GetForegroundWindow();
            char title[256]{};
            if (fg) GetWindowTextA(fg, title, sizeof(title));
            g_logger->log(std::string("Debug: Ctrl+V chatgpt=")
                          + (chatgpt ? "Y" : "N")
                          + " fg=" + title);
            if (chatgpt) {
                checkClipboardForEmail();
            }
        }
    }
    return CallNextHookEx(g_keyboardHook, nCode, wp, lp);
}

// Mechanism 2: mouse hook — catches right-click > Paste menu selection
static LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wp, LPARAM lp) {
    if (nCode == HC_ACTION) {
        if (wp == WM_RBUTTONDOWN) {
            // Right-click detected — if ChatGPT is foreground, arm the
            // context-menu tracker for up to 10 seconds
            if (isChatGPTForeground()) {
                g_contextMenuOpen = true;
                g_rightClickTime  = GetTickCount64();
            }
        } else if (wp == WM_LBUTTONDOWN && g_contextMenuOpen) {
            // Left-click while context menu is armed — user may have
            // clicked "Paste".  Check clipboard for email.
            ULONGLONG elapsed = GetTickCount64() - g_rightClickTime.load();
            g_contextMenuOpen = false;
            if (elapsed < 10000) {  // within 10 seconds of right-click
                if (isChatGPTForeground()) {
                    checkClipboardForEmail();
                }
            }
        }
    }
    return CallNextHookEx(g_mouseHook, nCode, wp, lp);
}

// Window proc for hidden window (handles drag-poll timer)
static LRESULT CALLBACK clipWndProc(HWND hwnd, UINT msg,
                                    WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_TIMER: {
        if (wp == DRAG_POLL_TIMER_ID) {
            onDragPollTimer();
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}

// ============================================================
// File-dialog monitor thread
//   Polls for the standard file-open dialog (#32770 / "Open"),
//   uses UI Automation to read the filename field, and on dialog
//   close checks the file's Google-Drive origin.
// ============================================================

// Find a visible "Open" file dialog
static HWND findFileDialog() {
    HWND hwnd = nullptr;
    while ((hwnd = FindWindowExW(nullptr, hwnd,
                                 L"#32770", nullptr)) != nullptr) {
        if (!IsWindowVisible(hwnd)) continue;
        wchar_t title[256]{};
        GetWindowTextW(hwnd, title, _countof(title));
        std::wstring t = toLowerW(title);
        if (t.find(L"open") != std::wstring::npos ||
            t.find(L"upload") != std::wstring::npos ||
            t.find(L"choose") != std::wstring::npos ||
            t.find(L"select") != std::wstring::npos) {
            return hwnd;
        }
    }
    return nullptr;
}

// Read the current folder from the file dialog using CDM_GETFOLDERPATH.
static std::wstring readDialogFolder(HWND hDialog) {
    // CDM_GETFOLDERPATH = WM_USER + 102
    const UINT CDM_GETFOLDERPATH_MSG = WM_USER + 102;
    // First call: get required buffer size
    LRESULT len = SendMessageW(hDialog, CDM_GETFOLDERPATH_MSG, 0, 0);
    if (len <= 0) return {};
    std::vector<wchar_t> buf(static_cast<size_t>(len) + 1, L'\0');
    SendMessageW(hDialog, CDM_GETFOLDERPATH_MSG,
                 static_cast<WPARAM>(buf.size()),
                 reinterpret_cast<LPARAM>(buf.data()));
    return std::wstring(buf.data());
}

// Read the filename from the dialog using CDM_GETSPEC.
static std::wstring readDialogSpec(HWND hDialog) {
    const UINT CDM_GETSPEC_MSG = WM_USER + 104;
    LRESULT len = SendMessageW(hDialog, CDM_GETSPEC_MSG, 0, 0);
    if (len <= 0) return {};
    std::vector<wchar_t> buf(static_cast<size_t>(len) + 1, L'\0');
    SendMessageW(hDialog, CDM_GETSPEC_MSG,
                 static_cast<WPARAM>(buf.size()),
                 reinterpret_cast<LPARAM>(buf.data()));
    std::wstring result(buf.data());
    // CDM_GETSPEC may return the filter pattern (e.g. "*.*") if no file selected
    if (result == L"*.*" || result == L"*") return {};
    return result;
}

// Read the full file path from the dialog using CDM_GETFILEPATH.
static std::wstring readDialogFilePath(HWND hDialog) {
    const UINT CDM_GETFILEPATH_MSG = WM_USER + 101;
    LRESULT len = SendMessageW(hDialog, CDM_GETFILEPATH_MSG, 0, 0);
    if (len <= 0) return {};
    std::vector<wchar_t> buf(static_cast<size_t>(len) + 1, L'\0');
    SendMessageW(hDialog, CDM_GETFILEPATH_MSG,
                 static_cast<WPARAM>(buf.size()),
                 reinterpret_cast<LPARAM>(buf.data()));
    return std::wstring(buf.data());
}

// Read filename using the file dialog's own combo box (control ID 0x047C).
static std::wstring readDialogComboFilename(HWND hDialog) {
    HWND hCombo = GetDlgItem(hDialog, 0x047C);  // cmb13 - filename combo
    if (!hCombo) return {};
    wchar_t buf[MAX_PATH]{};
    GetWindowTextW(hCombo, buf, MAX_PATH);
    std::wstring result(buf);
    if (result.empty() || result == L"*.*" || result == L"*") return {};
    return result;
}

// Read the selected filename from the dialog's list view via UI Automation.
static std::wstring readDialogListSelection(IUIAutomation* pAuto,
                                            HWND hDialog) {
    if (!pAuto) return {};

    IUIAutomationElement* pRoot = nullptr;
    if (FAILED(pAuto->ElementFromHandle(hDialog, &pRoot)) || !pRoot)
        return {};

    // Find list items with SelectionItem pattern that are selected
    VARIANT var;
    var.vt = VT_I4;
    var.lVal = UIA_ListItemControlTypeId;
    IUIAutomationCondition* pCond = nullptr;
    pAuto->CreatePropertyCondition(UIA_ControlTypePropertyId, var, &pCond);
    if (!pCond) { pRoot->Release(); return {}; }

    IUIAutomationElementArray* pArr = nullptr;
    pRoot->FindAll(TreeScope_Descendants, pCond, &pArr);
    pCond->Release();

    std::wstring result;
    if (pArr) {
        int cnt = 0;
        pArr->get_Length(&cnt);
        for (int i = 0; i < cnt && result.empty(); ++i) {
            IUIAutomationElement* pEl = nullptr;
            pArr->GetElement(i, &pEl);
            if (!pEl) continue;

            // Check if this item is selected
            IUIAutomationSelectionItemPattern* pSel = nullptr;
            HRESULT hr = pEl->GetCurrentPatternAs(
                UIA_SelectionItemPatternId,
                __uuidof(IUIAutomationSelectionItemPattern),
                reinterpret_cast<void**>(&pSel));
            if (SUCCEEDED(hr) && pSel) {
                BOOL isSelected = FALSE;
                pSel->get_CurrentIsSelected(&isSelected);
                if (isSelected) {
                    BSTR name = nullptr;
                    pEl->get_CurrentName(&name);
                    if (name) {
                        result = name;
                        SysFreeString(name);
                    }
                }
                pSel->Release();
            }
            pEl->Release();
        }
        pArr->Release();
    }
    pRoot->Release();
    return result;
}

// Read the "File name" edit field via UI Automation
static std::wstring readDialogFilename(IUIAutomation* pAuto,
                                       HWND hDialog) {
    if (!pAuto) return {};

    IUIAutomationElement* pRoot = nullptr;
    if (FAILED(pAuto->ElementFromHandle(hDialog, &pRoot)) || !pRoot)
        return {};

    VARIANT var;
    var.vt  = VT_I4;
    var.lVal = UIA_EditControlTypeId;

    IUIAutomationCondition* pCond = nullptr;
    HRESULT hr = pAuto->CreatePropertyCondition(
        UIA_ControlTypePropertyId, var, &pCond);
    if (FAILED(hr) || !pCond) { pRoot->Release(); return {}; }

    IUIAutomationElementArray* pArr = nullptr;
    hr = pRoot->FindAll(TreeScope_Descendants, pCond, &pArr);
    pCond->Release();

    std::wstring result;
    if (SUCCEEDED(hr) && pArr) {
        int cnt = 0;
        pArr->get_Length(&cnt);
        for (int i = 0; i < cnt && result.empty(); ++i) {
            IUIAutomationElement* pEl = nullptr;
            pArr->GetElement(i, &pEl);
            if (!pEl) continue;

            BSTR name = nullptr;
            pEl->get_CurrentName(&name);
            if (name) {
                std::wstring wn = toLowerW(name);
                SysFreeString(name);
                if (wn.find(L"file name") != std::wstring::npos ||
                    wn.find(L"filename")  != std::wstring::npos) {
                    IUIAutomationValuePattern* pVal = nullptr;
                    hr = pEl->GetCurrentPatternAs(
                        UIA_ValuePatternId,
                        __uuidof(IUIAutomationValuePattern),
                        reinterpret_cast<void**>(&pVal));
                    if (SUCCEEDED(hr) && pVal) {
                        BSTR v = nullptr;
                        pVal->get_CurrentValue(&v);
                        if (v) { result = v; SysFreeString(v); }
                        pVal->Release();
                    }
                }
            }
            pEl->Release();
        }
        pArr->Release();
    }
    pRoot->Release();
    return result;
}

// Attempt to resolve a filename (possibly relative) to a full path
// by checking well-known user folders.
static std::wstring resolveFilePath(const std::wstring& name) {
    if (name.empty()) return {};

    // If already absolute
    if (name.size() >= 2 && name[1] == L':') return name;

    // Try common locations
    std::vector<std::wstring> dirs;
    dirs.push_back(getDownloadsFolder());

    auto addFolder = [&](REFKNOWNFOLDERID id) {
        wchar_t* p = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) {
            dirs.emplace_back(p);
            CoTaskMemFree(p);
        }
    };
    addFolder(FOLDERID_Desktop);
    addFolder(FOLDERID_Documents);

    for (const auto& d : dirs) {
        if (d.empty()) continue;
        std::wstring candidate = d + L"\\" + name;
        if (fs::exists(candidate)) return candidate;
    }
    return {};
}

static void fileDialogMonitorThread() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    IUIAutomation* pAuto = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(CUIAutomation), nullptr,
                                 CLSCTX_INPROC_SERVER,
                                 __uuidof(IUIAutomation),
                                 reinterpret_cast<void**>(&pAuto));
    if (FAILED(hr) || !pAuto) {
        g_logger->log("Warning: UI Automation init failed; "
                      "file-dialog monitoring disabled.");
        CoUninitialize();
        return;
    }

    bool  dialogOpen  = false;
    DWORD dialogOwnerPid = 0;
    std::wstring lastFilename;
    std::wstring lastFolder;
    bool  dialogBlocked = false;   // cooldown: true after we blocked this dialog

    while (g_running) {
        Sleep(50);

        HWND hDlg = findFileDialog();

        if (hDlg) {
            if (!dialogOpen) {
                dialogOpen = true;
                dialogBlocked = false;
                GetWindowThreadProcessId(hDlg, &dialogOwnerPid);
                g_logger->log("Info: File-open dialog detected.");
            }

            // Try multiple methods to get the filename
            std::wstring fnEdit = readDialogFilename(pAuto, hDlg);
            std::wstring fnCombo = readDialogComboFilename(hDlg);
            std::wstring fnSpec = readDialogSpec(hDlg);
            std::wstring fnFullPath = readDialogFilePath(hDlg);
            std::wstring fnList = readDialogListSelection(pAuto, hDlg);

            std::wstring fn = fnEdit;
            if (fn.empty()) fn = fnCombo;
            if (fn.empty()) fn = fnSpec;
            if (fn.empty()) fn = fnList;

            if (!fn.empty() || !fnFullPath.empty()) {
                if (!fn.empty()) lastFilename = fn;
                if (!fnFullPath.empty()) lastFolder = L"";  // fullPath is absolute
            }

            // If we got a full path from CDM_GETFILEPATH, use it directly
            if (!fnFullPath.empty() && fnFullPath.size() >= 2 && fnFullPath[1] == L':') {
                lastFilename = fnFullPath;
                lastFolder = L"";
            }

            std::wstring folder = readDialogFolder(hDlg);
            if (!folder.empty() && lastFolder.empty()) lastFolder = folder;

            // --- Block Google Drive uploads while dialog is open ---
            // Use fnFullPath if available, otherwise fn
            std::wstring checkFn = fn;
            if (checkFn.empty() && !fnFullPath.empty()) checkFn = fnFullPath;
            if (!dialogBlocked && !checkFn.empty()) {
                bool chatGPTContext = isChatGPTForeground() ||
                                     processHasChatGPTWindow(dialogOwnerPid) ||
                                     anyChatGPTWindowExists();
                if (chatGPTContext) {
                    // Build full path: if checkFn is relative, prepend the
                    // dialog's current folder (or fall back to resolveFilePath)
                    std::wstring fullPath;
                    if (checkFn.size() >= 2 && checkFn[1] == L':') {
                        fullPath = checkFn;  // already absolute
                    } else {
                        std::wstring folder = readDialogFolder(hDlg);
                        if (!folder.empty()) {
                            if (folder.back() != L'\\') folder += L'\\';
                            fullPath = folder + checkFn;
                        } else {
                            fullPath = resolveFilePath(checkFn);
                        }
                    }

                    g_logger->log("Debug: block-check file=" + wideToUtf8(checkFn)
                                  + " fullPath=" + wideToUtf8(fullPath));

                    bool detected = false;
                    if (!fullPath.empty() && fs::exists(fullPath)) {
                        detected = isFromGoogleDrive(fullPath);
                        g_logger->log("Debug: block-check ads=" +
                                      std::string(detected ? "Y" : "N"));
                    }

                    if (detected) {
                        g_logger->log(
                            "Alert: Drive-sourced file upload to ChatGPT blocked. file="
                            + wideToUtf8(fullPath));

                        // STRATEGY: Lock the file with exclusive access so
                        // Chrome cannot read it for upload. Hold the lock
                        // for a few seconds on a background thread.
                        std::wstring lockPath = fullPath;
                        std::thread([lockPath]() {
                            HANDLE hLock = CreateFileW(
                                lockPath.c_str(),
                                GENERIC_READ,
                                0,  // no sharing — exclusive lock
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
                            if (hLock != INVALID_HANDLE_VALUE) {
                                g_logger->log("Debug: File locked: " +
                                              wideToUtf8(lockPath));
                                // Hold lock long enough for Chrome's upload
                                // attempt to fail
                                Sleep(5000);
                                CloseHandle(hLock);
                                g_logger->log("Debug: File unlocked: " +
                                              wideToUtf8(lockPath));
                            } else {
                                g_logger->log("Debug: Failed to lock file: " +
                                              wideToUtf8(lockPath) + " err=" +
                                              std::to_string(GetLastError()));
                            }
                        }).detach();

                        dialogBlocked = true;
                        std::thread([]() {
                            MessageBoxW(nullptr,
                                L"Upload blocked: the selected file originated "
                                L"from Google Drive and cannot be uploaded to "
                                L"ChatGPT.",
                                L"ChatGPT Agent",
                                MB_OK | MB_ICONWARNING);
                        }).detach();
                    }
                }
            }

        } else if (dialogOpen) {
            // Dialog just closed
            dialogOpen = false;

            g_logger->log("Debug: Dialog closed. filename="
                          + (lastFilename.empty() ? std::string("(empty)")
                                                  : wideToUtf8(lastFilename)));

            bool chatGPTContext = isChatGPTForeground() ||
                                 processHasChatGPTWindow(dialogOwnerPid) ||
                                 anyChatGPTWindowExists();
            g_logger->log(std::string("Debug: chatGPT=")
                          + (chatGPTContext ? "Y" : "N"));

            if (chatGPTContext && !lastFilename.empty() && !dialogBlocked) {
                // Build full path from dialog folder + filename
                std::wstring fullPath;
                if (lastFilename.size() >= 2 && lastFilename[1] == L':') {
                    fullPath = lastFilename;
                } else if (!lastFolder.empty()) {
                    std::wstring f = lastFolder;
                    if (f.back() != L'\\') f += L'\\';
                    fullPath = f + lastFilename;
                } else {
                    fullPath = resolveFilePath(lastFilename);
                }

                g_logger->log("Debug: close-check file=" + wideToUtf8(lastFilename)
                              + " fullPath=" + wideToUtf8(fullPath));

                bool detected = false;
                if (!fullPath.empty() && fs::exists(fullPath)) {
                    detected = isFromGoogleDrive(fullPath);
                    g_logger->log("Debug: close-check ads=" +
                                  std::string(detected ? "Y" : "N"));
                }

                if (detected) {
                    g_logger->log(
                        "Alert: Drive-sourced file upload to ChatGPT detected. file="
                        + wideToUtf8(fullPath));
                }
            }
            lastFilename.clear();
            lastFolder.clear();
            dialogOwnerPid = 0;
        }
    }

    pAuto->Release();
    CoUninitialize();
}

// ============================================================
// Graceful shutdown on Ctrl+C
// ============================================================
static BOOL WINAPI consoleCtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT) {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ============================================================
// main
// ============================================================
int main() {
    Logger logger("chatGPT_agent.log");
    g_logger = &logger;

    g_logger->log("=== ChatGPT Agent started ===");
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);

    // Worker thread
    std::thread tDialog(fileDialogMonitorThread);

    // Message-only window (clipboard listener + clipboard access)
    WNDCLASSW wc{};
    wc.lpfnWndProc   = clipWndProc;
    wc.hInstance      = GetModuleHandle(nullptr);
    wc.lpszClassName  = L"ChatGPTAgent_ClipMon";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", 0,
                                0, 0, 0, 0,
                                HWND_MESSAGE, nullptr,
                                wc.hInstance, nullptr);
    if (!hwnd) {
        g_logger->log("Error: Failed to create hidden window.");
        g_running = false;
        tDialog.join();
        return 1;
    }
    g_hiddenWnd = hwnd;

    // Install low-level keyboard hook (for Ctrl+V paste detection)
    g_keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, keyboardHookProc,
                                       GetModuleHandle(nullptr), 0);
    if (!g_keyboardHook) {
        g_logger->log("Warning: Failed to install keyboard hook; "
                      "Ctrl+V paste detection unavailable.");
    }

    // Install low-level mouse hook (for right-click paste detection)
    g_mouseHook = SetWindowsHookExW(WH_MOUSE_LL, mouseHookProc,
                                     GetModuleHandle(nullptr), 0);
    if (!g_mouseHook) {
        g_logger->log("Warning: Failed to install mouse hook; "
                      "right-click paste detection unavailable.");
    }

    // Start poll timer for drag-and-drop detection
    SetTimer(g_hiddenWnd, DRAG_POLL_TIMER_ID, DRAG_POLL_INTERVAL, nullptr);

    g_logger->log("Info: Paste monitoring active (keyboard + mouse hooks).");
    g_logger->log("Info: File-dialog monitoring active.");
    g_logger->log("Info: Drag-drop monitoring active.");
    g_logger->log("Info: Agent running – press Ctrl+C to stop.");

    std::cout << "ChatGPT Agent running.  Log: chatGPT_agent.log\n"
              << "Press Ctrl+C to stop.\n";

    // Win32 message loop
    MSG msg;
    while (g_running) {
        if (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) break;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        } else {
            MsgWaitForMultipleObjects(0, nullptr, FALSE,
                                      500, QS_ALLINPUT);
        }
    }

    KillTimer(g_hiddenWnd, DRAG_POLL_TIMER_ID);
    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = nullptr;
    }
    if (g_mouseHook) {
        UnhookWindowsHookEx(g_mouseHook);
        g_mouseHook = nullptr;
    }
    DestroyWindow(hwnd);
    g_logger->log("Info: Shutting down...");

    if (tDialog.joinable()) tDialog.join();

    g_logger->log("=== ChatGPT Agent stopped ===");
    return 0;
}
