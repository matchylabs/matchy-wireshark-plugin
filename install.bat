@echo off
setlocal enabledelayedexpansion

:: Install matchy-wireshark-plugin for Windows
:: Run by double-clicking or from command prompt: install.bat [version]

echo Matchy Wireshark Plugin Installer
echo =================================
echo.

:: Get script directory
set "SCRIPT_DIR=%~dp0"

:: Get package version (what the plugin was built for)
set "PACKAGE_VERSION="
if exist "%SCRIPT_DIR%MIN_WIRESHARK_VERSION" (
    set /p PACKAGE_VERSION=<"%SCRIPT_DIR%MIN_WIRESHARK_VERSION"
)

:: Check for version argument first
set "TARGET_VERSION=%~1"

:: If no argument, try to detect user's installed Wireshark
if "%TARGET_VERSION%"=="" (
    :: Try tshark first
    where tshark >nul 2>&1
    if !errorlevel!==0 (
        for /f "tokens=2 delims= " %%v in ('tshark --version 2^>nul ^| findstr /r "^TShark"') do (
            for /f "tokens=1,2 delims=." %%a in ("%%v") do (
                set "TARGET_VERSION=%%a.%%b"
            )
        )
    )
)

:: If still no version, try Wireshark config file
if "%TARGET_VERSION%"=="" (
    set "RECENT_FILE=%APPDATA%\Wireshark\recent"
    if exist "!RECENT_FILE!" (
        for /f "usebackq tokens=3 delims= " %%v in (`findstr /r "^# Wireshark" "!RECENT_FILE!" 2^>nul`) do (
            for /f "tokens=1,2 delims=." %%a in ("%%v") do (
                set "TARGET_VERSION=%%a.%%b"
            )
        )
    )
)

:: If still nothing, fall back to package version
if "%TARGET_VERSION%"=="" (
    if not "%PACKAGE_VERSION%"=="" (
        set "TARGET_VERSION=%PACKAGE_VERSION%"
        echo Could not detect Wireshark version, using package version.
    )
)

if "%TARGET_VERSION%"=="" (
    echo ERROR: Could not determine Wireshark version
    echo.
    echo Please specify the version manually:
    echo   install.bat 4.6
    echo.
    echo To find your Wireshark version:
    echo   - Open Wireshark and go to Help -^> About
    echo   - Or run: tshark --version
    echo.
    goto :pause_exit
)

echo Detected Wireshark version: %TARGET_VERSION%

:: Warn if package version differs from detected version
if not "%PACKAGE_VERSION%"=="" (
    if not "%PACKAGE_VERSION%"=="%TARGET_VERSION%" (
        echo.
        echo WARNING: Version mismatch
        echo   Plugin built for: %PACKAGE_VERSION%
        echo   Your Wireshark:   %TARGET_VERSION%
        echo   The plugin may not load correctly.
        echo.
    )
)

:: Set up plugin directory
set "PLUGIN_DIR=%APPDATA%\Wireshark\plugins\%TARGET_VERSION%\epan"
echo Plugin directory: %PLUGIN_DIR%
echo.

:: Create directory if needed
if not exist "%PLUGIN_DIR%" (
    echo Creating plugin directory...
    mkdir "%PLUGIN_DIR%" 2>nul
    if errorlevel 1 (
        echo ERROR: Failed to create directory %PLUGIN_DIR%
        goto :pause_exit
    )
)

:: Find source DLL
set "PLUGIN_SRC="
if exist "%SCRIPT_DIR%matchy.dll" (
    set "PLUGIN_SRC=%SCRIPT_DIR%matchy.dll"
) else if exist "%SCRIPT_DIR%target\release\matchy_wireshark_plugin.dll" (
    set "PLUGIN_SRC=%SCRIPT_DIR%target\release\matchy_wireshark_plugin.dll"
)

if "%PLUGIN_SRC%"=="" (
    echo ERROR: Plugin DLL not found
    echo Expected locations:
    echo   - %SCRIPT_DIR%matchy.dll
    echo   - %SCRIPT_DIR%target\release\matchy_wireshark_plugin.dll
    goto :pause_exit
)

echo Installing from: %PLUGIN_SRC%

:: Copy plugin
copy /y "%PLUGIN_SRC%" "%PLUGIN_DIR%\matchy.dll" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy plugin
    goto :pause_exit
)

echo.
echo Installation complete!
echo.
echo Verify installation:
echo   - Open Wireshark and go to Help -^> About Wireshark -^> Plugins
echo   - Look for 'matchy' in the list
echo.
echo Or run:
echo   tshark -G plugins ^| findstr matchy
echo.
echo Configuration:
echo   1. Open Wireshark
echo   2. Go to Edit -^> Preferences -^> Protocols -^> Matchy
echo   3. Browse to select your .mxy threat database file
echo.
echo Or use environment variable:
echo   set MATCHY_DATABASE=C:\path\to\threats.mxy
echo.

:pause_exit
:: Pause so user can see output if double-clicked
echo Press any key to exit...
pause >nul
