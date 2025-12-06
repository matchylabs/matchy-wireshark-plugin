@echo off
setlocal enabledelayedexpansion

:: Install matchy-wireshark-plugin for Windows
:: Run by double-clicking or from command prompt

echo Matchy Wireshark Plugin Installer
echo =================================
echo.

:: Get script directory
set "SCRIPT_DIR=%~dp0"

:: Check if this is a multi-version package (has plugins\ directory)
if exist "%SCRIPT_DIR%plugins" (
    call :install_all_versions
) else (
    echo ERROR: plugins directory not found
    echo This doesn't appear to be a valid matchy-wireshark-plugin package.
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
goto :pause_exit

:install_all_versions
echo Installing plugin for all supported Wireshark versions...
echo.
set "INSTALLED=0"

for /d %%d in ("%SCRIPT_DIR%plugins\*") do (
    set "VERSION=%%~nd%%~xd"
    set "PLUGIN_SRC=%%d\matchy.dll"
    
    if exist "!PLUGIN_SRC!" (
        call :install_version "!VERSION!" "!PLUGIN_SRC!"
        set /a INSTALLED+=1
    )
)

if !INSTALLED!==0 (
    echo ERROR: No plugin DLLs found in plugins\
    goto :pause_exit
)

echo.
echo Installed !INSTALLED! plugin version^(s^)
goto :eof

:install_version
set "VERSION=%~1"
set "PLUGIN_SRC=%~2"
set "PLUGIN_DIR=%APPDATA%\Wireshark\plugins\%VERSION%\epan"

echo   Installing for Wireshark %VERSION% -^> %PLUGIN_DIR%

if not exist "%PLUGIN_DIR%" (
    mkdir "%PLUGIN_DIR%" 2>nul
)

copy /y "%PLUGIN_SRC%" "%PLUGIN_DIR%\matchy.dll" >nul
if errorlevel 1 (
    echo     ERROR: Failed to copy plugin
)
goto :eof

:pause_exit
echo Press any key to exit...
pause >nul
