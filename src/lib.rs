//! Matchy Wireshark Plugin
//!
//! Real-time threat intelligence matching for packet analysis.
//! Integrates matchy threat databases into Wireshark as a postdissector plugin.
//!
//! # Features
//!
//! - Real-time IP/domain threat lookups during packet capture
//! - Custom display filters for threat queries
//! - Automatic packet colorization by threat level
//! - Sub-millisecond performance on 100K+ indicators
//!
//! # Architecture
//!
//! The plugin acts as a Wireshark postdissector, processing packets after
//! normal dissection. It extracts source/destination IPs and domains,
//! queries them against a matchy threat database, and adds custom fields
//! to the packet tree for display and filtering.

mod wireshark_ffi;
mod postdissector;
mod display_filter;
mod threats;

use libc::{c_char, c_int};
use std::ffi::CStr;
use std::sync::{Arc, Mutex};

/// Global threat database (lazily loaded)
static THREAT_DB: Mutex<Option<Arc<matchy::Database>>> = Mutex::new(None);

/// Plugin version
const VERSION: &str = "0.1.0";

/// Plugin name
const PLUGIN_NAME: &str = "Matchy";

/// Plugin description
const PLUGIN_DESCRIPTION: &str = "Real-time threat intelligence matching for packet analysis";

/// Wireshark plugin entry point
/// Called when plugin is loaded by Wireshark
#[no_mangle]
pub extern "C" fn plugin_register() {
    // Register the postdissector
    // This will be called for each packet after normal dissection
    postdissector::register_postdissector();
}

/// Get plugin information (called by Wireshark)
#[no_mangle]
pub extern "C" fn plugin_register_info(info: *mut plugin_info_t) {
    if info.is_null() {
        return;
    }

    unsafe {
        (*info).version = VERSION.as_ptr() as *const c_char;
        (*info).name = PLUGIN_NAME.as_ptr() as *const c_char;
        (*info).description = PLUGIN_DESCRIPTION.as_ptr() as *const c_char;
    }
}

/// Load a threat database
///
/// # Arguments
///
/// * `path` - C string path to .mxy threat database file
///
/// # Returns
///
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn matchy_wireshark_load_database(path: *const c_char) -> c_int {
    if path.is_null() {
        return -1;
    }

    let path_str = match unsafe { CStr::from_ptr(path).to_str() } {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match matchy::Database::from(path_str).open() {
        Ok(db) => {
            if let Ok(mut threat_db) = THREAT_DB.lock() {
                *threat_db = Some(Arc::new(db));
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Get current threat database status
///
/// # Returns
///
/// 1 if database loaded, 0 if not loaded
#[no_mangle]
pub extern "C" fn matchy_wireshark_database_loaded() -> c_int {
    match THREAT_DB.lock() {
        Ok(db) => {
            if db.is_some() {
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

/// Placeholder for plugin info structure
/// This will be defined more completely in the Wireshark FFI bindings
#[repr(C)]
pub struct plugin_info_t {
    version: *const c_char,
    name: *const c_char,
    description: *const c_char,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_plugin_constants() {
        assert_eq!(PLUGIN_NAME, "Matchy");
        assert!(PLUGIN_DESCRIPTION.contains("threat intelligence"));
    }
}
