# ChatGPT Agent For Data Loss Prevention 

A Windows user-space agent that monitors ChatGPT browser interactions to prevent data loss. It detects email addresses in pasted text and blocks file uploads originating from Google Drive.

## Building

### Requirements

- Windows 10 or later
- MinGW-w64 (g++) with C++17 support, or MSVC (`cl`)

### Compile with g++ (MinGW)

```
set PATH=C:\msys64\ucrt64\bin;%PATH%
g++ -std=c++17 -O2 -static -o chatGPT_agent.exe chatGPT_agent.cpp -lole32 -loleaut32 -lshell32 -lshlwapi -luser32 -luuid
```

or with

```
build.bat
```

## Running

```
chatGPT_agent.exe
```

The agent runs in the foreground and logs to `chatGPT_agent.log` in the current directory. Press `Ctrl+C` to stop.

## Features

### 1. Email Detection in Pasted Text

Detects email addresses in clipboard content pasted into ChatGPT via:

- **Ctrl+V / Ctrl+Shift+V** keyboard shortcuts (keyboard hook)
- **Right-click > Paste** context menu (mouse hook)

### 2. Google Drive File Upload Blocking (File Dialog)

When a user opens a file-upload dialog from ChatGPT and selects a file that originated from Google Drive, the agent:

- Logs an alert
- Locks the file with exclusive access to prevent the browser from reading it
- Shows a popup notification

### 3. Google Drive File Drag-and-Drop Detection

Detects drag-and-drop operations from Explorer to ChatGPT browser windows using event-driven mouse hook detection. When a Google Drive file is dragged over a ChatGPT window, the agent simulates an Escape keypress to cancel the drag.

## OS APIs Used

### Window and Input Hooks

| API | Purpose |
|-----|---------|
| `SetWindowsHookExW(WH_KEYBOARD_LL, ...)` | Low-level keyboard hook to intercept Ctrl+V paste keystrokes system-wide |
| `SetWindowsHookExW(WH_MOUSE_LL, ...)` | Low-level mouse hook to detect right-click paste and drag-and-drop operations |
| `CallNextHookEx` | Forwards hook events to the next handler in the chain |
| `SendInput` | Simulates keyboard input (Escape key) to cancel drag-and-drop operations |

### Window Management

| API | Purpose |
|-----|---------|
| `GetForegroundWindow` | Identifies the currently active window to check if ChatGPT is in focus |
| `GetWindowTextW` | Reads window titles to identify ChatGPT browser tabs |
| `EnumWindows` | Enumerates all top-level windows to find ChatGPT sessions |
| `FindWindowExW` | Locates file-open dialogs (window class `#32770`) |
| `WindowFromPoint` | Identifies the window under the cursor during drag operations |
| `GetParent` | Walks the window hierarchy to find top-level parent windows |
| `CreateWindowExW` | Creates a hidden message-only window for clipboard monitoring |
| `SetForegroundWindow` | Brings the file dialog to the foreground for cancellation |
| `GetDlgItem` | Accesses child controls (filename edit, Cancel button) within file dialogs |
| `SetWindowTextW` | Clears the filename field in file dialogs |

### Clipboard

| API | Purpose |
|-----|---------|
| `OpenClipboard` / `CloseClipboard` | Accesses clipboard data |
| `GetClipboardData(CF_UNICODETEXT)` | Reads text from the clipboard for email detection |

### UI Automation (COM)

| API | Purpose |
|-----|---------|
| `IUIAutomation` | Main COM interface for UI Automation |
| `IUIAutomationElement::FindAll` | Searches for Edit and ListItem controls within windows |
| `IUIAutomationValuePattern` | Reads the value of text fields (browser address bar, file dialog filename) |
| `IUIAutomationSelectionItemPattern` | Checks which file is selected in the file dialog's list view |

UI Automation is used for two purposes:
1. **Browser URL detection** — reads the address bar of Chrome/Edge/Firefox to check if the URL contains `chatgpt.com`
2. **File dialog monitoring** — reads the filename field and selected items in file-open dialogs

### Shell COM Interfaces (Explorer Integration)

| API | Purpose |
|-----|---------|
| `IShellWindows` (`CLSID_ShellWindows`) | Enumerates all open Explorer windows |
| `IWebBrowserApp::get_HWND` | Gets the HWND of each Explorer window for filtering |
| `IServiceProvider::QueryService` | Navigates from the shell window to the shell browser |
| `IShellBrowser::QueryActiveShellView` | Gets the active view (file list) of an Explorer window |
| `IShellView::GetItemObject(SVGIO_SELECTION)` | Gets the data object representing the selected files |
| `IDataObject::GetData(CF_HDROP)` | Extracts file paths from the selection |
| `DragQueryFileW` | Reads individual file paths from an `HDROP` handle |

These are used during drag-and-drop detection to determine which files the user has selected in Explorer.

### File Dialog Messages

| Message | Purpose |
|---------|---------|
| `CDM_GETFOLDERPATH` (`WM_USER + 102`) | Gets the current folder path from the file dialog |
| `CDM_GETSPEC` (`WM_USER + 104`) | Gets the filename specified in the dialog |
| `CDM_GETFILEPATH` (`WM_USER + 101`) | Gets the full file path from the dialog |
| `CDM_SETCONTROLTEXT` (`WM_USER + 105`) | Sets text on a dialog control |

### File System

| API | Purpose |
|-----|---------|
| `CreateFileW` | Opens files — used both for reading Zone.Identifier ADS and for exclusive file locking |
| `ReadFile` | Reads the content of NTFS alternate data streams |
| `SHGetKnownFolderPath` | Locates the user's Downloads, Desktop, and Documents folders |
| `QueryFullProcessImageNameW` | Gets the executable path of a process to identify `explorer.exe` |

### Process and Threading

| API | Purpose |
|-----|---------|
| `GetWindowThreadProcessId` | Gets the process ID owning a window |
| `OpenProcess` | Opens a process handle for querying its executable name |
| `SetConsoleCtrlHandler` | Handles Ctrl+C for graceful shutdown |

## How File Origin Detection Works

The agent detects whether a file was downloaded from Google Drive by reading the **NTFS Alternate Data Stream (ADS)** named `Zone.Identifier`.

When a browser downloads a file on Windows, it writes metadata to the file's `Zone.Identifier` ADS. This stream contains information about where the file came from, including:

```ini
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://drive.google.com/...
HostUrl=https://drive.usercontent.google.com/download?id=...
```

The agent reads this stream by opening `<filepath>:Zone.Identifier` and checking whether the content contains `drive.google.com` or `drive.usercontent.google.com`.

## Limitations

### File Origin Detection

- **NTFS-only**: The Zone.Identifier information is an NTFS (New Technology File System) feature. Files on FAT32, exFAT, or network shares do not have this metadata. Files from Google Drive on non-NTFS volumes will not be detected.
- **ADS can be stripped**: Users or tools can remove the Zone.Identifier stream (e.g., by right-clicking the file > Properties > Unblock, or using `Remove-Item -Stream Zone.Identifier`). Once stripped, the file's origin cannot be detected.
- **Copy/move may lose ADS**: Copying a file to a non-NTFS volume and back, or using certain file managers, will strip the Zone.Identifier. Extracting files from a ZIP archive also loses the ADS.
- **Filename collisions**: If a locally-created file has the same name as a Drive file and is in the same folder, the detection is based on the actual file at that path, which is correct. However, if the file dialog doesn't provide the full path, the agent falls back to searching known folders, which could match the wrong file.

### File Upload Blocking

- **Race condition**: The agent polls the file dialog every 50ms. If the user double-clicks a file (which simultaneously selects and opens it), the dialog may close before the agent detects the filename. In this case, the agent detects and logs the event but may not prevent the upload.
- **File locking timing**: The agent locks the file with exclusive access to prevent the browser from reading it. If the browser has already opened the file before the lock is acquired, the upload proceeds.
- **Browser-dependent**: The file dialog detection relies on the standard Windows file dialog. Custom file pickers or browser-specific dialogs may not be detected.

### Drag-and-Drop Blocking

- **Event-driven detection**: The drag-and-drop monitor uses a low-level mouse hook to detect drag operations. It triggers when the mouse moves beyond a threshold while the button is held down over an Explorer window.
- **Explorer selection vs. dragged file**: The agent queries the Explorer window's current selection, which normally matches the file being dragged. However, if multiple files are selected, all are checked.
- **Escape simulation**: Cancelling a drag by simulating an Escape keypress is not guaranteed to work in all scenarios. If the drop completes before the Escape is processed, the agent can only alert after the fact.

### Paste/Email Detection

- **Email regex only**: Email detection is based on mail address patterns.
- **No content inspection**: The agent checks clipboard text, not what is actually submitted to ChatGPT. If the user modifies the text after pasting, the alert may be a false positive or the modified text may not be checked.
- **Browser-specific title matching**: ChatGPT window detection relies on the window title containing "chatgpt" or the browser address bar containing "chatgpt.com". If the page title changes or the URL format changes, detection may fail.

### General

- **User-space only**: The agent runs entirely in user space without kernel drivers or browser extensions. A determined user can bypass all protections by terminating the agent, stripping ADS metadata, or using a browser not detected by the agent.
- **Single-machine scope**: The agent only monitors the local machine. Files uploaded from other devices or via mobile are not covered.
- **No network inspection**: The agent does not inspect network traffic. It relies entirely on file metadata and UI-level monitoring.
