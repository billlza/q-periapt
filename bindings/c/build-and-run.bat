@echo off
REM Build the q-periapt-ffi cdylib, verify its exact ABI2 DLL exports, and link
REM bindings/c/smoke.c against it with MSVC, then run the C-ABI link smoke test.
REM Locates the MSVC toolchain via vswhere (so it
REM works even when cl.exe is not on PATH). Run from anywhere:  bindings\c\build-and-run.bat
setlocal enabledelayedexpansion
cd /d "%~dp0\..\.."

echo [1/4] cargo +1.97.0 build -p q-periapt-ffi --release
cargo +1.97.0 build -p q-periapt-ffi --release --locked || exit /b 1

echo [2/4] locate MSVC (vswhere -^> vcvars64)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" echo ERROR: Visual Studio Build Tools not found & exit /b 1
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1

set "OUT=target\release"
echo [3/4] verify exact ABI2 DLL exports
python artifact\c_abi_contract.py --library "%OUT%\q_periapt_ffi_abi2.dll" --platform windows || exit /b 1

echo [4/4] cl smoke.c + link q_periapt_ffi_abi2.dll.lib, then run
cl /nologo /W4 /WX /utf-8 bindings\c\smoke.c /I crates\q-periapt-ffi\include /Fe:"%OUT%\c_smoke.exe" /Fo:"%OUT%\c_smoke.obj" /link "%OUT%\q_periapt_ffi_abi2.dll.lib" || exit /b 1
"%OUT%\c_smoke.exe"
exit /b %ERRORLEVEL%
