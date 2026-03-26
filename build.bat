@echo off
echo ============================================
echo   wow_optimize v2.0.8 build script
echo   Builds: wow_optimize.dll + version.dll
echo   Requires: Visual Studio 2026 + CMake
echo ============================================
echo.

where cmake >nul 2>nul
if errorlevel 1 (
    echo ERROR: CMake not found.
    echo Install Visual Studio 2026 with "Desktop development with C++"
    pause
    exit /b 1
)

if not exist build mkdir build
cd build

echo [1/3] Configuring (32-bit)...
cmake -G "Visual Studio 18 2026" -A Win32 .. 2>&1
if errorlevel 1 (
    rd /s /q CMakeFiles
    del /q CMakeCache.txt
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
echo Output files:
echo   build\Release\wow_optimize.dll  - optimization DLL
echo   build\Release\version.dll       - auto-loader proxy
echo.
echo OPTION A (recommended):
echo   Copy BOTH files to your WoW folder. No injector needed.
echo.
echo OPTION B (manual):
echo   Copy wow_optimize.dll + use inject.bat or any DLL injector.
echo.
cd ..
pause
