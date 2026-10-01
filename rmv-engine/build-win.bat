@echo off
REM Build preload.so (RMV exploit) with NDK r29 on Windows.
REM Mirrors the Linux Makefile: PROJECT=PD2520-BP2A.250605.031.A3 API=34
setlocal
set NDK=C:\neo11\tools\android-ndk-r29
set BIN=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\bin
set CC=%BIN%\clang.exe
set SYSROOT=%NDK%\toolchains\llvm\prebuilt\windows-x86_64\sysroot
set SRC=C:\neo11\exploit\exploit
set PROJECT=PD2520-BP2A.250605.031.A3
set OUTDIR=%SRC%\build\%PROJECT%\bin
set EMBEDDIR=%SRC%\build\embed
set API=34

if not exist %OUTDIR% mkdir %OUTDIR%
if not exist %EMBEDDIR% mkdir %EMBEDDIR%

set CFLAGS=-O2 -g0 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function -I%SRC%\src -DTARGET_CONFIG_H=\"targets/%PROJECT%/target.h\"
set SO_FLAGS=-fPIC %CFLAGS%
set PIE_FLAGS=-fPIE -pie %CFLAGS%
set LDFLAGS=-fuse-ld=lld -Wl,-rpath-link,%SYSROOT%\usr\lib\aarch64-linux-android\%API% -L%SYSROOT%\usr\lib\aarch64-linux-android\%API% -L%SYSROOT%\usr\lib\aarch64-linux-android
set SO_EXTRA=-lc -ldl -Wl,--gc-sections -Wl,-soname,preload.so

REM 1) standalone su binary (embedded into preload.so)
echo [1/2] building su_daemon_aarch64_pie ...
%CC% --target=aarch64-linux-android%API% --sysroot=%SYSROOT% %PIE_FLAGS% %SRC%\src\su_daemon.c %LDFLAGS% -Wl,-dynamic-linker,/system/bin/linker64 -o %EMBEDDIR%\su_daemon_aarch64_pie
if errorlevel 1 goto :fail

REM 2) preload.so
echo [2/2] building preload.so ...
cd /d %SRC%
%CC% --target=aarch64-linux-android%API% --sysroot=%SYSROOT% %SO_FLAGS% ^
  %SRC%\src\main.c %SRC%\src\util.c %SRC%\src\slide.c %SRC%\src\fops.c ^
  %SRC%\src\pipe.c %SRC%\src\posture.c %SRC%\src\preload.c %SRC%\src\su_blob.S ^
  %SRC%\src\targets\%PROJECT%\root.c %SRC%\src\safety.c ^
  %LDFLAGS% %SO_EXTRA% -shared -pthread -o %OUTDIR%\preload.so
if errorlevel 1 goto :fail

echo BUILD OK: %OUTDIR%\preload.so
certutil -hashfile %OUTDIR%\preload.so SHA256 | findstr /v /i "certutil command"
goto :eof

:fail
echo BUILD FAILED
exit /b 1
