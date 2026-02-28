@echo off
echo =================================
echo   wow_optimize.dll injector
echo =================================
echo.

if not exist Wow.exe (
    echo ERROR: inject.bat must be in the same folder as Wow.exe
    echo Copy all files to your World of Warcraft directory.
    echo.
    pause
    exit /b 1
)

if not exist wow_optimize.dll (
    echo ERROR: wow_optimize.dll not found in current folder.
    echo.
    pause
    exit /b 1
)

if not exist Dll_Injector.exe (
    echo ERROR: Dll_Injector.exe not found in current folder.
    echo.
    pause
    exit /b 1
)

echo Waiting for Wow.exe to be running...
echo Make sure WoW is launched and you see the login screen.
echo.

:wait_loop
tasklist /FI "IMAGENAME eq Wow.exe" 2>NUL | find /I /N "Wow.exe" >NUL
if errorlevel 1 (
    echo WoW is not running. Waiting...
    timeout /t 2 /nobreak >NUL
    goto wait_loop
)

echo WoW detected! Injecting in 3 seconds...
timeout /t 3 /nobreak >NUL

Dll_Injector.exe wow.exe wow_optimize.dll

echo.
echo Check wow_optimize.log to verify.
echo.
pause