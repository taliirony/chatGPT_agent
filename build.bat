@echo off
set PATH=C:\msys64\ucrt64\bin;%PATH%
g++ -std=c++17 -O2 -static -o chatGPT_agent.exe chatGPT_agent.cpp -lole32 -loleaut32 -lshell32 -lshlwapi -luser32 -luuid
if %errorlevel%==0 (
    echo Build succeeded.
) else (
    echo Build failed.
)
