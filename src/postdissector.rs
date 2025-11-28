//! Wireshark postdissector implementation
//!
//! A postdissector runs after normal dissection, allowing us to add
//! custom fields based on threat intelligence lookups.

use crate::wireshark_ffi::*;
use libc::c_int;
use std::sync::Once;

// Global protocol ID (assigned by Wireshark during registration)
static mut PROTO_MATCHY: c_int = -1;

// Header field IDs
static mut HF_THREAT_DETECTED: c_int = -1;
static mut HF_THREAT_LEVEL: c_int = -1;
static mut HF_THREAT_CATEGORY: c_int = -1;
static mut HF_THREAT_SOURCE: c_int = -1;

// Ensure registration only happens once
static REGISTER_ONCE: Once = Once::new();

/// Register the postdissector with Wireshark
pub fn register_postdissector() {
    REGISTER_ONCE.call_once(|| {
        unsafe {
            // Register our protocol
            PROTO_MATCHY = register_protocol(
                "Matchy Threat Intelligence",
                "Matchy",
                "matchy",
            );

            // Register header fields
            // TODO: Implement proper field array registration
            // For now, we'll add fields dynamically during dissection

            // Register the postdissector callback
            register_postdissector_callback(dissect_packet, PROTO_MATCHY);
        }
    });
}

/// Postdissector callback - processes each packet
///
/// This is called by Wireshark after all normal dissection is complete.
///
/// # Safety
///
/// This function is called from C code and must handle null pointers safely.
pub unsafe extern "C" fn dissect_packet(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    _data: *mut libc::c_void,
) -> c_int {
    // Safety checks
    if tvb.is_null() || pinfo.is_null() {
        return 0;
    }

    // Skip if no tree (Wireshark sometimes calls dissectors without building a tree)
    if tree.is_null() {
        return 0;
    }

    // TODO: Implement actual packet processing:
    // 1. Extract source/destination IPs from pinfo
    // 2. Extract domain names from already-dissected protocols (DNS, TLS SNI, HTTP Host)
    // 3. Query matchy database for each indicator
    // 4. Add custom fields to the display tree
    // 5. Set packet coloring based on threat level

    DISSECTOR_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postdissector_registration() {
        // TODO: Test that postdissector can be registered
    }
}
