@echo off
echo ============================================
echo   wow_optimize.dll BY SUPREMATIST build script
echo   Requires: Visual Studio 2022 + CMake
echo ============================================
echo.

where cmake >nul 2>nul
if errorlevel 1 (
    echo ERROR: CMake not found.
    echo Install Visual Studio 2022 with "Desktop development with C++"
    pause
    exit /b 1
)

if not exist build mkdir build
cd build

echo [1/3] Configuring ^(32-bit^)...
cmake -G "Visual Studio 17 2022" -A Win32 .. 2>&1
if errorlevel 1 (
    echo Trying Visual Studio 2019...
    cmake -G "Visual Studio 16 2019" -A Win32 .. 2>&1
    if errorlevel 1 (
        echo ERROR: CMake configure failed.
        cd ..
        pause
        exit /b 1
    )
)

echo.
echo [2/3] Building Release...
cmake --build . --config Release 2>&1
if errorlevel 1 (
    echo ERROR: Build failed.
    cd ..
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo.
echo Output: build\Release\wow_optimize.dll
echo Copy it to your WoW folder and inject.
echo.
cd ..
pause