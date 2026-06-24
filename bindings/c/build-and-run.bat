@echo off
REM Build the q-periapt-ffi cdylib and link bindings/c/smoke.c against it with MSVC,
REM then run the C-ABI link smoke test. Locates the MSVC toolchain via vswhere (so it
REM works even when cl.exe is not on PATH). Run from anywhere:  bindings\c\build-and-run.bat
setlocal enabledelayedexpansion
cd /d "%~dp0\..\.."

echo [1/3] cargo build -p q-periapt-ffi --release
cargo build -p q-periapt-ffi --release || exit /b 1

echo [2/3] locate MSVC (vswhere -^> vcvars64)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" echo ERROR: Visual Studio Build Tools not found & exit /b 1
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

echo [3/3] cl smoke.c + link q_periapt_ffi.dll.lib, then run
set "OUT=target\release"
cl /nologo /W3 /utf-8 bindings\c\smoke.c /I crates\q-periapt-ffi\include /Fe:"%OUT%\c_smoke.exe" /Fo:"%OUT%\c_smoke.obj" /link "%OUT%\q_periapt_ffi.dll.lib" || exit /b 1
"%OUT%\c_smoke.exe"
exit /b %ERRORLEVEL%
