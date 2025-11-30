//! Matchy Wireshark Plugin Installer
//!
//! Detects Wireshark installations, checks version compatibility,
//! and installs the plugin to the correct location.

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Wireshark major.minor version this plugin was built for
const PLUGIN_WIRESHARK_VERSION: &str = env!("WIRESHARK_VERSION");

/// Plugin version
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
struct WiresharkInstallation {
    /// Type of installation (app, homebrew-arm, homebrew-intel, system, etc.)
    install_type: String,
    /// Major.minor version (e.g., "4.6")
    version: String,
    /// Path prefix (e.g., /opt/homebrew, /Applications/Wireshark.app)
    prefix: PathBuf,
    /// Path to tshark or wireshark binary
    binary: PathBuf,
}

impl WiresharkInstallation {
    fn display_name(&self) -> String {
        format!("{} (Wireshark {})", self.install_type, self.version)
    }

    fn plugin_dir(&self) -> PathBuf {
        let version_dir = self.version.replace('.', "-");
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".local/lib/wireshark/plugins")
            .join(&version_dir)
            .join("epan")
    }

    fn is_compatible(&self, plugin_version: &str) -> bool {
        // Compare major.minor versions
        let install_parts: Vec<&str> = self.version.split('.').collect();
        let plugin_parts: Vec<&str> = plugin_version.split('.').collect();

        if install_parts.len() >= 2 && plugin_parts.len() >= 2 {
            install_parts[0] == plugin_parts[0] && install_parts[1] == plugin_parts[1]
        } else {
            false
        }
    }

    fn glib_path(&self) -> Option<PathBuf> {
        match self.install_type.as_str() {
            "Wireshark.app" => {
                // App bundles its own frameworks, use @rpath
                None
            }
            "Homebrew (ARM)" => {
                let path = PathBuf::from("/opt/homebrew/opt/glib/lib/libglib-2.0.0.dylib");
                if path.exists() {
                    Some(path)
                } else {
                    None
                }
            }
            "Homebrew (Intel)" => {
                let path = PathBuf::from("/usr/local/opt/glib/lib/libglib-2.0.0.dylib");
                if path.exists() {
                    Some(path)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn detect_installations() -> Vec<WiresharkInstallation> {
    let mut installations = Vec::new();

    #[cfg(target_os = "macos")]
    {
        // Check Wireshark.app
        let app_path = PathBuf::from("/Applications/Wireshark.app");
        if app_path.exists() {
            let binary = app_path.join("Contents/MacOS/Wireshark");
            if let Some(version) = get_wireshark_version(&binary) {
                installations.push(WiresharkInstallation {
                    install_type: "Wireshark.app".to_string(),
                    version,
                    prefix: app_path.clone(),
                    binary,
                });
            }
        }

        // Check Homebrew ARM
        let brew_arm = PathBuf::from("/opt/homebrew/bin/tshark");
        if brew_arm.exists() {
            if let Some(version) = get_wireshark_version(&brew_arm) {
                installations.push(WiresharkInstallation {
                    install_type: "Homebrew (ARM)".to_string(),
                    version,
                    prefix: PathBuf::from("/opt/homebrew"),
                    binary: brew_arm,
                });
            }
        }

        // Check Homebrew Intel
        let brew_intel = PathBuf::from("/usr/local/bin/tshark");
        if brew_intel.exists() {
            if let Some(version) = get_wireshark_version(&brew_intel) {
                installations.push(WiresharkInstallation {
                    install_type: "Homebrew (Intel)".to_string(),
                    version,
                    prefix: PathBuf::from("/usr/local"),
                    binary: brew_intel,
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Check system installation
        if let Ok(output) = Command::new("which").arg("tshark").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let binary = PathBuf::from(&path);
                if let Some(version) = get_wireshark_version(&binary) {
                    installations.push(WiresharkInstallation {
                        install_type: "System".to_string(),
                        version,
                        prefix: PathBuf::from("/usr"),
                        binary,
                    });
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Check Program Files
        let paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ];
        for path in paths {
            let binary = PathBuf::from(path);
            if binary.exists() {
                if let Some(version) = get_wireshark_version(&binary) {
                    installations.push(WiresharkInstallation {
                        install_type: "Windows".to_string(),
                        version,
                        prefix: binary.parent().unwrap().to_path_buf(),
                        binary,
                    });
                }
            }
        }
    }

    // Fallback: check PATH
    if installations.is_empty() {
        if let Ok(output) = Command::new("tshark").arg("--version").output() {
            if output.status.success() {
                if let Some(version) = parse_version_output(&output.stdout) {
                    installations.push(WiresharkInstallation {
                        install_type: "PATH".to_string(),
                        version,
                        prefix: PathBuf::new(),
                        binary: PathBuf::from("tshark"),
                    });
                }
            }
        }
    }

    installations
}

fn get_wireshark_version(binary: &Path) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;
    if output.status.success() {
        parse_version_output(&output.stdout)
    } else {
        None
    }
}

fn parse_version_output(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    // Parse "TShark (Wireshark) 4.6.1" or "Wireshark 4.6.1"
    for line in text.lines() {
        if line.contains("Wireshark") || line.contains("TShark") {
            // Find version number pattern
            let parts: Vec<&str> = line.split_whitespace().collect();
            for part in parts {
                if part.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    // Extract major.minor
                    let version_parts: Vec<&str> = part.split('.').collect();
                    if version_parts.len() >= 2 {
                        return Some(format!("{}.{}", version_parts[0], version_parts[1]));
                    }
                }
            }
        }
    }
    None
}

fn find_plugin_binary() -> Option<PathBuf> {
    // Look for the plugin in common locations
    let exe_dir = env::current_exe().ok()?.parent()?.to_path_buf();

    let candidates = [
        // Same directory as installer
        exe_dir.join("libmatchy_wireshark.dylib"),
        exe_dir.join("libmatchy_wireshark.so"),
        exe_dir.join("matchy_wireshark.dll"),
        // Cargo target directory
        exe_dir.join("../libmatchy_wireshark.dylib"),
        exe_dir.join("../libmatchy_wireshark.so"),
        // Current directory
        PathBuf::from("target/release/libmatchy_wireshark.dylib"),
        PathBuf::from("target/release/libmatchy_wireshark.so"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate.canonicalize().ok()?);
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn fix_macos_library_paths(plugin_path: &Path, installation: &WiresharkInstallation) -> io::Result<()> {
    use std::process::Command;

    // Set library ID
    let _ = Command::new("install_name_tool")
        .args(["-id", "matchy.so"])
        .arg(plugin_path)
        .output();

    // Get current library references
    let otool_output = Command::new("otool")
        .args(["-L"])
        .arg(plugin_path)
        .output()?;

    let output_str = String::from_utf8_lossy(&otool_output.stdout);

    // Fix wireshark/wsutil to use @rpath
    for lib in ["libwireshark", "libwsutil"] {
        for line in output_str.lines() {
            if line.contains(lib) && !line.contains("@rpath") {
                let old_path: String = line.trim().split_whitespace().next().unwrap_or("").to_string();
                if !old_path.is_empty() {
                    let lib_name = Path::new(&old_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    let new_path = format!("@rpath/{}", lib_name);
                    let _ = Command::new("install_name_tool")
                        .args(["-change", &old_path, &new_path])
                        .arg(plugin_path)
                        .output();
                }
            }
        }
    }

    // Fix glib path based on installation type
    if let Some(glib_path) = installation.glib_path() {
        for line in output_str.lines() {
            if line.contains("libglib-2.0") {
                let old_path: String = line.trim().split_whitespace().next().unwrap_or("").to_string();
                if !old_path.is_empty() && old_path != glib_path.to_string_lossy() {
                    let _ = Command::new("install_name_tool")
                        .args(["-change", &old_path, &glib_path.to_string_lossy()])
                        .arg(plugin_path)
                        .output();
                }
            }
        }
    }

    Ok(())
}

fn prompt_selection(installations: &[WiresharkInstallation]) -> Option<usize> {
    println!("\nDetected Wireshark installations:\n");

    for (i, install) in installations.iter().enumerate() {
        let compat = if install.is_compatible(PLUGIN_WIRESHARK_VERSION) {
            "\x1b[32m[compatible]\x1b[0m"
        } else {
            "\x1b[33m[version mismatch]\x1b[0m"
        };
        println!("  {}. {} {}", i + 1, install.display_name(), compat);
    }

    println!("\nPlugin was built for Wireshark {}", PLUGIN_WIRESHARK_VERSION);
    println!();

    loop {
        print!("Select installation (1-{}), or 'q' to quit: ", installations.len());
        io::stdout().flush().ok()?;

        let mut input = String::new();
        io::stdin().lock().read_line(&mut input).ok()?;
        let input = input.trim();

        if input.eq_ignore_ascii_case("q") {
            return None;
        }

        if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= installations.len() {
                return Some(num - 1);
            }
        }

        println!("Invalid selection. Please enter a number between 1 and {}.", installations.len());
    }
}

fn install_plugin(
    plugin_src: &Path,
    installation: &WiresharkInstallation,
) -> io::Result<()> {
    let plugin_dir = installation.plugin_dir();
    let plugin_dest = plugin_dir.join("matchy.so");

    // Create plugin directory
    fs::create_dir_all(&plugin_dir)?;

    println!("\nInstalling to: {}", plugin_dest.display());

    // Copy plugin
    fs::copy(plugin_src, &plugin_dest)?;

    // Fix library paths on macOS
    #[cfg(target_os = "macos")]
    {
        println!("Fixing macOS library paths...");
        fix_macos_library_paths(&plugin_dest, installation)?;
    }

    Ok(())
}

fn main() {
    println!("Matchy Wireshark Plugin Installer v{}", PLUGIN_VERSION);
    println!("========================================\n");

    // Find plugin binary
    let plugin_src = match find_plugin_binary() {
        Some(path) => {
            println!("Found plugin: {}", path.display());
            path
        }
        None => {
            eprintln!("\x1b[31mError: Could not find plugin binary.\x1b[0m");
            eprintln!("Please build first: cargo build --release");
            std::process::exit(1);
        }
    };

    // Detect installations
    let installations = detect_installations();

    if installations.is_empty() {
        eprintln!("\x1b[31mError: No Wireshark installation found.\x1b[0m");
        eprintln!("\nPlease install Wireshark:");
        eprintln!("  macOS:   brew install wireshark");
        eprintln!("           or https://www.wireshark.org/download.html");
        eprintln!("  Linux:   apt install wireshark / dnf install wireshark");
        eprintln!("  Windows: https://www.wireshark.org/download.html");
        std::process::exit(1);
    }

    // If only one installation and it's compatible, install directly
    let selected = if installations.len() == 1 && installations[0].is_compatible(PLUGIN_WIRESHARK_VERSION) {
        println!("Found: {}", installations[0].display_name());
        Some(0)
    } else {
        prompt_selection(&installations)
    };

    let Some(idx) = selected else {
        println!("Installation cancelled.");
        return;
    };

    let installation = &installations[idx];

    // Warn about version mismatch
    if !installation.is_compatible(PLUGIN_WIRESHARK_VERSION) {
        println!("\n\x1b[33mWarning: Version mismatch!\x1b[0m");
        println!("  Plugin built for: Wireshark {}", PLUGIN_WIRESHARK_VERSION);
        println!("  Target version:   Wireshark {}", installation.version);
        println!("\nThe plugin may not load correctly or could crash Wireshark.");
        print!("Continue anyway? [y/N] ");
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().lock().read_line(&mut input).is_err() {
            return;
        }
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Installation cancelled.");
            return;
        }
    }

    // Install
    match install_plugin(&plugin_src, installation) {
        Ok(()) => {
            println!("\n\x1b[32mInstallation complete!\x1b[0m\n");
            println!("Verify with:");
            println!("  tshark -G plugins | grep matchy\n");
            println!("Usage:");
            println!("  MATCHY_DATABASE=/path/to/threats.mxy wireshark capture.pcap\n");
        }
        Err(e) => {
            eprintln!("\n\x1b[31mInstallation failed: {}\x1b[0m", e);
            std::process::exit(1);
        }
    }
}

// Minimal dirs implementation for home directory
mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        #[cfg(unix)]
        {
            std::env::var("HOME").ok().map(PathBuf::from)
        }
        #[cfg(windows)]
        {
            std::env::var("USERPROFILE").ok().map(PathBuf::from)
        }
    }
}
