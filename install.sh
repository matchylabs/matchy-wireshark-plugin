#!/bin/sh
# Install matchy-wireshark-plugin
#
# This script installs the matchy Wireshark plugin to the user's plugin directory.
# It supports both macOS and Linux systems.
#
# POSIX-compliant - works with /bin/sh, dash, bash, zsh, etc.

set -e

# Get script directory (POSIX-compatible)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Detect OS type
detect_os() {
    case "$(uname -s)" in
        Darwin*) echo "darwin" ;;
        Linux*)  echo "linux" ;;
        *)       echo "unknown" ;;
    esac
}

OS_TYPE="$(detect_os)"

info() { printf "${GREEN}%s${NC}\n" "$1"; }
error() { printf "${RED}%s${NC}\n" "$1"; }

# Extract major.minor version from Wireshark version string
extract_version() {
    echo "$1" | sed -E 's/.*([0-9]+\.[0-9]+)\..*/\1/' | head -1
}

# Detect Wireshark version from config file
detect_version_from_config() {
    # Check both possible config locations
    for recent_file in "$HOME/.config/wireshark/recent" "$HOME/.wireshark/recent"; do
        if [ -f "$recent_file" ]; then
            version=$(head -1 "$recent_file" | sed -E 's/.*Wireshark ([0-9]+\.[0-9]+)\..*/\1/')
            if [ -n "$version" ] && echo "$version" | grep -qE '^[0-9]+\.[0-9]+$'; then
                echo "$version"
                return
            fi
        fi
    done
}

# Detect Wireshark version from binary
detect_version_from_binary() {
    # Try wireshark, then tshark
    for bin in wireshark tshark; do
        if command -v "$bin" >/dev/null 2>&1; then
            version=$("$bin" --version 2>/dev/null | head -1)
            extract_version "$version"
            return
        fi
    done
    
    # macOS: check Wireshark.app
    if [ "$OS_TYPE" = "darwin" ] && [ -d "/Applications/Wireshark.app" ]; then
        version=$(/Applications/Wireshark.app/Contents/MacOS/Wireshark --version 2>/dev/null | head -1)
        extract_version "$version"
        return
    fi
}

# Detect Wireshark version - prefer config file, fall back to binary
detect_wireshark_version() {
    # Config file is most reliable (works even if binary not in PATH)
    version=$(detect_version_from_config)
    if [ -n "$version" ]; then
        echo "$version"
        return
    fi
    
    # Fall back to binary detection
    detect_version_from_binary
}

# Build the plugin (for source tree installs)
build_plugin() {
    echo "Building plugin..."
    (cd "$SCRIPT_DIR" && cargo build --release)
}

# Install a single plugin version to user directory
install_plugin_version() {
    version="$1"
    plugin_src="$2"
    
    # macOS uses dashes (4-6), Linux uses dots (4.6)
    if [ "$OS_TYPE" = "darwin" ]; then
        version_dir=$(echo "$version" | tr '.' '-')
    else
        version_dir="$version"
    fi
    plugin_dir="$HOME/.local/lib/wireshark/plugins/${version_dir}/epan"
    plugin_name="matchy.so"
    
    echo "  Installing for Wireshark $version -> $plugin_dir"
    
    mkdir -p "$plugin_dir"
    cp "$plugin_src" "$plugin_dir/$plugin_name"
    
    # macOS: Remove quarantine attribute (for downloaded binaries)
    if [ "$OS_TYPE" = "darwin" ]; then
        xattr -d com.apple.quarantine "$plugin_dir/$plugin_name" 2>/dev/null || true
        
        # Fix library paths to use @rpath
        install_name_tool -id "$plugin_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
        
        for lib in libwireshark libwsutil libglib-2.0; do
            old_path=$(otool -L "$plugin_dir/$plugin_name" | grep "$lib" | awk '{print $1}' | head -1)
            if [ -n "$old_path" ]; then
                case "$old_path" in
                    @rpath/*) ;;  # Already using @rpath, skip
                    *)
                        lib_name=$(basename "$old_path")
                        install_name_tool -change "$old_path" "@rpath/$lib_name" "$plugin_dir/$plugin_name" 2>/dev/null || true
                        ;;
                esac
            fi
        done
        
        # Re-sign after modifying library paths (required on modern macOS)
        codesign -f -s - "$plugin_dir/$plugin_name" 2>/dev/null || true
    fi
}

# Install all plugin versions from package
install_all_versions() {
    plugins_dir="$SCRIPT_DIR/plugins"
    
    if [ ! -d "$plugins_dir" ]; then
        error "Error: plugins directory not found"
        return 1
    fi
    
    installed=0
    for version_dir in "$plugins_dir"/*/; do
        if [ -d "$version_dir" ]; then
            version=$(basename "$version_dir")
            plugin_src="${version_dir}matchy.so"
            if [ -f "$plugin_src" ]; then
                install_plugin_version "$version" "$plugin_src"
                installed=$((installed + 1))
            fi
        fi
    done
    
    if [ "$installed" -eq 0 ]; then
        error "Error: No plugin binaries found in plugins/"
        return 1
    fi
    
    info "Installed $installed plugin version(s)"
}

# Install from source tree (single version)
install_from_source() {
    version="$1"
    
    plugin_src=""
    if [ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.dylib" ]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.dylib"
    elif [ -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.so" ]; then
        plugin_src="$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.so"
    else
        error "Error: Plugin binary not found. Run: cargo build --release"
        return 1
    fi
    
    install_plugin_version "$version" "$plugin_src"
    info "Installed 1 plugin version"
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    if [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
        echo "  --build       Force rebuild before installing"
    fi
    echo "  --help        Show this help message"
}

# Main
main() {
    force_build=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --build) force_build=true; shift ;;
            --help) usage; exit 0 ;;
            *) error "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
    
    echo "Matchy Wireshark Plugin Installer"
    echo "================================="
    echo
    
    # Check if this is a binary package (has plugins/ directory) or source tree
    if [ -d "$SCRIPT_DIR/plugins" ]; then
        # Binary package - install all bundled versions
        info "Installing plugin for all supported Wireshark versions..."
        install_all_versions
    elif [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
        # Source tree - detect version and build if needed
        installed_version=$(detect_wireshark_version)
        
        if [ -z "$installed_version" ]; then
            error "Error: Could not detect Wireshark version"
            echo
            echo "Please install Wireshark:"
            echo "  macOS:  brew install wireshark  OR  https://www.wireshark.org/download.html"
            echo "  Linux:  apt install wireshark / dnf install wireshark"
            exit 1
        fi
        
        info "Detected Wireshark $installed_version"
        
        if [ "$force_build" = true ] || { [ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.dylib" ] && \
                                           [ ! -f "$SCRIPT_DIR/target/release/libmatchy_wireshark_plugin.so" ]; }; then
            build_plugin
        fi
        
        install_from_source "$installed_version"
    else
        error "Error: Not a valid matchy-wireshark-plugin package"
        exit 1
    fi
    
    echo
    info "Installation complete!"
    echo
    echo "Verify installation:"
    echo "  tshark -G plugins | grep matchy"
    echo
    echo "Configuration:"
    echo "  1. Open Wireshark"
    echo "  2. Go to Edit → Preferences → Protocols → Matchy"
    echo "  3. Browse to select your .mxy threat database file"
}

# Pause if running interactively (e.g., double-clicked from file manager)
# This keeps the terminal window open so the user can read the output
pause_if_interactive() {
    # Only pause if stdin is a terminal and we're not being piped
    if [ -t 0 ] && [ -t 1 ]; then
        # Check if we're likely launched from a GUI (no parent shell)
        # ppid=1 or parent is a GUI app typically means double-clicked
        case "$(ps -o comm= -p $PPID 2>/dev/null)" in
            # Common terminal emulators - don't pause
            bash|zsh|sh|dash|fish|ksh|tcsh|csh) ;;
            # Everything else (Finder, Nautilus, etc.) - pause
            *)
                printf "Press Enter to close..."
                read -r _
                ;;
        esac
    fi
}

main "$@"
pause_if_interactive
