@echo off
REM Build RMV preload.so for multiple third-party GhostLock targets.
REM Usage: build_ports.bat [PROJECT ...]   (default: all four ports)
setlocal enabledelayedexpansion
set NDK=C:\neo11\tools\android-ndk-r29
set BIN=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin
set CC=%BIN%\clang.exe
set SYSROOT=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\sysroot
set SRC=C:\neo11\exploit\exploit
set EMBEDDIR=%SRC%\build\embed
set API=34

if "%~1"=="" (
  set PROJECTS=I2401-16.1.22.2 PD2426-BP2A.250605.031.A3 PD2415-BP2A.250605.031.A3 PD2405-AP3A.240905.015.A1
) else (
  set PROJECTS=%*
)

if not exist %EMBEDDIR% mkdir %EMBEDDIR%

set CFLAGS=-O2 -g0 -Wall -Wextra -Wno-unused-parameter -Wno-sign-comcompare -Wno-unused-function -I%SRC%\src -DTARGET_CONFIG_H=\"targets/%%PROJECT%%/target.h\"
set SO_FLAGS=-fPIC -O2 -g0 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -I%SRC%\src
set LDFLAGS=-fuse-ld=lld -Wl,-rpath-link,%SYSROOT%\usr\lib\aarch64-linux-android\%API% -L%SYSROOT%\usr\lib\aarch64-linux-android\%API% -L%SYSROOT%\usr\lib\aarch64-linux-android
set SO_EXTRA=-lc -ldl -Wl,--gc-sections -Wl,-soname,preload.so

REM su_daemon embedded binary is target-independent (built once, reused)
if not exist %EMBEDDIR%\su_daemon_aarch64_pie (
  echo [0] building su_daemon_aarch64_pie ...
  %CC% --target=aarch64-linux-android%API% --sysroot=%SYSROOT% -fPIE -pie -O2 -g0 -I%SRC%\src ^
    %SRC%\src\su_daemon.c %LDFLAGS% -Wl,-dynamic-linker,/system/bin/linker64 -o %EMBEDDIR%\su_daemon_aarch64_pie
  if errorlevel 1 goto :fail
)

for %%P in (%PROJECTS%) do (
  echo.
  echo ===== building preload.so for %%P =====
  set PROJECT=%%P
  set OUTDIR=%SRC%\build\%%P\bin
  if not exist !OUTDIR! mkdir !OUTDIR!
  cd /d %SRC%
  %CC% --target=aarch64-linux-android%API% --sysroot=%SYSROOT% !SO_FLAGS! ^
    -DTARGET_CONFIG_H=\"targets/%%P/target.h\" ^
    %SRC%\src\main.c %SRC%\src\util.c %SRC%\src\slide.c %SRC%\src\fops.c %SRC%\src\proof.c ^
    %SRC%\src\pipe.c %SRC%\src\posture.c %SRC%\src\preload.c %SRC%\src\su_blob.S ^
    %SRC%\src\targets\%%P\root.c %SRC%\src\safety.c ^
    !LDFLAGS! !SO_EXTRA! -shared -pthread -o !OUTDIR!\preload.so
  if errorlevel 1 goto :fail
  echo BUILD OK: !OUTDIR!\preload.so
  for %%F in (!OUTDIR!\preload.so) do echo   size: %%~zF
)

echo.
echo ALL BUILDS OK
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
