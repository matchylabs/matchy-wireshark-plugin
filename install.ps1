# Install matchy-wireshark-plugin for Windows
#
# This script installs the matchy Wireshark plugin to the user's plugin directory.
# Run with: .\install.ps1
#
# Requires: PowerShell 5.1+ (included in Windows 10+)

param(
    [string]$Version,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Colors
function Write-Success {
    param([string]$msg)
    Write-Host $msg -ForegroundColor Green
}
function Write-Err {
    param([string]$msg)
    Write-Host $msg -ForegroundColor Red
}
function Write-Info {
    param([string]$msg)
    Write-Host $msg -ForegroundColor Cyan
}

function Show-Usage {
    Write-Host "Matchy Wireshark Plugin Installer"
    Write-Host ""
    Write-Host "Usage: .\install.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version <version>  Specify Wireshark version (e.g., 4.6)"
    Write-Host "  -Help               Show this help message"
    Write-Host ""
    Write-Host "If -Version is not specified, uses WIRESHARK_VERSION from package."
}

function Get-VersionFromConfig {
    # Try to detect version from Wireshark config file
    # Works for both installed and portable versions
    $recentFile = Join-Path $env:APPDATA "Wireshark\recent"
    
    if (Test-Path $recentFile) {
        try {
            $firstLine = Get-Content $recentFile -First 1
            if ($firstLine -match 'Wireshark (\d+\.\d+)') {
                return $matches[1]
            }
        } catch {
            # Silently ignore errors when probing for Wireshark
        }
    }
    
    return $null
}

function Find-WiresharkVersion {
    # Try to find Wireshark installations (best-effort, not required)
    # Returns array of version strings found
    $foundVersions = @()
    
    # Check config file first (works for portable)
    $configVer = Get-VersionFromConfig
    if ($configVer) {
        $foundVersions += $configVer
    }
    
    # Check PATH for tshark
    $tshark = Get-Command tshark -ErrorAction SilentlyContinue
    if ($tshark) {
        try {
            $output = & tshark --version 2>&1 | Select-Object -First 1
            if ($output -match '(\d+\.\d+)') {
                $ver = $matches[1]
                if ($ver -notin $foundVersions) {
                    $foundVersions += $ver
                }
            }
        } catch {
            # Silently ignore errors when probing for tshark
        }
    }
    
    # Check PATH for Wireshark.exe
    $wireshark = Get-Command Wireshark -ErrorAction SilentlyContinue
    if ($wireshark) {
        try {
            $output = & $wireshark -v 2>&1 | Select-Object -First 1
            if ($output -match '(\d+\.\d+)') {
                $ver = $matches[1]
                if ($ver -notin $foundVersions) {
                    $foundVersions += $ver
                }
            }
        } catch {
            # Silently ignore errors when probing for Wireshark
        }
    }
    
    return $foundVersions
}

function Get-PackageVersion {
    $versionFile = Join-Path $PSScriptRoot "WIRESHARK_VERSION"
    if (Test-Path $versionFile) {
        $ver = (Get-Content $versionFile -Raw).Trim()
        if ($ver -match '^\d+\.\d+') {
            return $ver
        }
    }
    return $null
}

function Install-Plugin {
    param(
        [string]$Version
    )
    
    # Plugin directory: %APPDATA%\Wireshark\plugins\X.Y\epan
    $pluginDir = Join-Path $env:APPDATA "Wireshark\plugins\$Version\epan"
    $pluginName = "matchy.dll"
    
    Write-Host ""
    Write-Info "Installing for Wireshark $Version"
    Write-Host "  Plugin directory: $pluginDir"
    
    # Create directory if needed
    if (-not (Test-Path $pluginDir)) {
        New-Item -ItemType Directory -Force -Path $pluginDir | Out-Null
    }
    
    # Find source DLL
    $pluginSrc = $null
    $candidates = @(
        (Join-Path $PSScriptRoot "matchy.dll"),
        (Join-Path $PSScriptRoot "target\release\matchy_wireshark_plugin.dll")
    )
    
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            $pluginSrc = $candidate
            break
        }
    }
    
    if (-not $pluginSrc) {
        Write-Err "Error: Plugin DLL not found"
        Write-Host "Expected locations:"
        foreach ($c in $candidates) {
            Write-Host "  - $c"
        }
        exit 1
    }
    
    # Copy plugin
    Copy-Item $pluginSrc -Destination (Join-Path $pluginDir $pluginName) -Force
    
    Write-Success "  Installed successfully"
}

# Main
if ($Help) {
    Show-Usage
    exit 0
}

Write-Host "Matchy Wireshark Plugin Installer"
Write-Host "================================="
Write-Host ""

# Determine version to install for
$targetVersion = $Version
if (-not $targetVersion) {
    $targetVersion = Get-PackageVersion
}

if (-not $targetVersion) {
    Write-Err "Error: Could not determine Wireshark version"
    Write-Host ""
    Write-Host "Please specify the version manually:"
    Write-Host "  .\install.ps1 -Version 4.6"
    Write-Host ""
    Write-Host "To find your Wireshark version:"
    Write-Host "  - Open Wireshark and go to Help -> About"
    Write-Host "  - Or run: tshark --version"
    exit 1
}

if ($targetVersion -notmatch '^\d+\.\d+') {
    Write-Err "Error: Invalid version format '$targetVersion'"
    Write-Host "Expected format: X.Y (e.g., 4.6)"
    exit 1
}

Write-Info "Target Wireshark version: $targetVersion"

# Try to detect installed Wireshark (best-effort)
$foundVersions = Find-WiresharkVersion
if ($foundVersions.Count -gt 0) {
    Write-Host "Detected Wireshark: $($foundVersions -join ', ')"
    
    # Check for version mismatch
    if ($targetVersion -notin $foundVersions) {
        Write-Host ""
        Write-Host "WARNING: Version mismatch detected" -ForegroundColor Yellow
        Write-Host "  Plugin built for: $targetVersion" -ForegroundColor Yellow
        Write-Host "  Found installed: $($foundVersions -join ', ')" -ForegroundColor Yellow
        Write-Host "  The plugin may not work correctly." -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "Note: Could not auto-detect Wireshark installation"
    Write-Host "  (This is OK for portable installations)"
}

Write-Host ""
Install-Plugin -Version $targetVersion

Write-Host ""
Write-Success "Installation complete!"
Write-Host ""
Write-Host "Verify installation:"
Write-Host "  - Open Wireshark and go to Help -> About Wireshark -> Plugins"
Write-Host "  - Look for 'matchy' in the list"
Write-Host ""
Write-Host "Or run:"
Write-Host "  tshark -G plugins | Select-String matchy"
Write-Host ""
Write-Host "Configuration:"
Write-Host "  1. Open Wireshark"
Write-Host "  2. Go to Edit -> Preferences -> Protocols -> Matchy"
Write-Host "  3. Browse to select your .mxy threat database file"
Write-Host ""
Write-Host "Or use environment variable:"
Write-Host "  `$env:MATCHY_DATABASE = 'C:\path\to\threats.mxy'"
Write-Host ""

# Pause if run by double-clicking (not from a terminal)
if ([Environment]::UserInteractive -and -not [Console]::IsOutputRedirected) {
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
