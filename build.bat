@echo off
setlocal enabledelayedexpansion

if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not exist build mkdir build

echo [OpenRAR] Compiling rar.exe ...
cl.exe /nologo /std:c++17 /utf-8 /O2 /EHsc /W3 /I"include" ^
    src\rar_crypto.cpp ^
    src\rar_codec.cpp ^
    src\rar_archive.cpp ^
    src\rar_cli.cpp ^
    src\main.cpp ^
    /Fo"build\\" /Fe"rar.exe" ^
    shell32.lib advapi32.lib

if %ERRORLEVEL% NEQ 0 (
    echo [OpenRAR] Build failed!
    exit /b %ERRORLEVEL%
)

copy /Y rar.exe unrar-free.exe >nul
echo [OpenRAR] Successfully built rar.exe and unrar-free.exe
