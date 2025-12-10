//! Matchy Wireshark Plugin
//!
//! Real-time threat intelligence matching for packet analysis.
//! Integrates matchy threat databases into Wireshark as a postdissector plugin.

// Wireshark's plugin API requires mutable statics for field registration.
// This is safe because Wireshark initializes plugins single-threaded.
#![allow(static_mut_refs)]

mod postdissector;
mod threats;
mod wireshark_ffi;

use libc::{c_char, c_int};
use std::ffi::CStr;
use std::sync::Mutex;

/// Global threat database handle
static THREAT_DB: Mutex<Option<matchy::Database>> = Mutex::new(None);

/// Database path preference (pointer to C string)
static mut DATABASE_PATH: *const c_char = std::ptr::null();

/// Toolbar status entry (for updating database info display)
static mut TOOLBAR_STATUS_ENTRY: *mut wireshark_ffi::ext_toolbar_t = std::ptr::null_mut();

/// Dissector handle (stored for use in final registration)
static mut DISSECTOR_HANDLE: wireshark_ffi::dissector_handle_t = std::ptr::null_mut();

/// Flag to track if we need to update toolbar on first dissection
/// (toolbar widget isn't ready during preferences_apply)
static mut TOOLBAR_NEEDS_UPDATE: bool = false;


/// Global protocol ID (set during registration)
static mut PROTO_MATCHY: c_int = -1;

/// Header field IDs
static mut HF_THREAT_DETECTED: c_int = -1;
static mut HF_THREAT_LEVEL: c_int = -1;
static mut HF_THREAT_CATEGORY: c_int = -1;
static mut HF_THREAT_SOURCE: c_int = -1;
static mut HF_THREAT_INDICATOR: c_int = -1;
static mut HF_THREAT_INDICATOR_TYPE: c_int = -1;
// ThreatDB optional fields
static mut HF_THREAT_CONFIDENCE: c_int = -1;
static mut HF_THREAT_TLP: c_int = -1;
static mut HF_THREAT_LAST_SEEN: c_int = -1;

/// Subtree index
static mut ETT_MATCHY: c_int = -1;

// ============================================================================
// Plugin Version Information
// ============================================================================

// Plugin version and Wireshark compatibility version - auto-generated from Cargo.toml
include!(concat!(env!("OUT_DIR"), "/version.rs"));

// ============================================================================
// Proto Plugin Structure
// ============================================================================

/// Proto plugin structure - tells Wireshark which functions to call
#[repr(C)]
struct ProtoPlugin {
    register_protoinfo: Option<unsafe extern "C" fn()>,
    register_handoff: Option<unsafe extern "C" fn()>,
}

/// Static plugin descriptor
static PROTO_PLUGIN: ProtoPlugin = ProtoPlugin {
    register_protoinfo: Some(proto_register_matchy),
    register_handoff: Some(proto_reg_handoff_matchy),
};

// ============================================================================
// Plugin Entry Point
// ============================================================================

#[cfg_attr(target_os = "windows", link(name = "libwireshark", kind = "raw-dylib"))]
extern "C" {
    fn proto_register_plugin(plugin: *const ProtoPlugin);
}

/// Plugin registration - called by Wireshark at startup
///
/// This registers our plugin with Wireshark's plugin system.
/// Wireshark will then call our register_protoinfo and register_handoff
/// functions at the appropriate times during initialization.
#[no_mangle]
pub extern "C" fn plugin_register() {
    unsafe {
        proto_register_plugin(&PROTO_PLUGIN);
    }
}

// ============================================================================
// Protocol Registration (called by Wireshark during protocol init)
// ============================================================================

/// Called by Wireshark to register our protocol and fields
#[no_mangle]
unsafe extern "C" fn proto_register_matchy() {
    use wireshark_ffi::*;

    // Register the protocol
    static NAME: &[u8] = b"Matchy Threat Intelligence\0";
    static SHORT_NAME: &[u8] = b"Matchy\0";
    static FILTER_NAME: &[u8] = b"matchy\0";

    PROTO_MATCHY = proto_register_protocol(
        NAME.as_ptr() as *const c_char,
        SHORT_NAME.as_ptr() as *const c_char,
        FILTER_NAME.as_ptr() as *const c_char,
    );

    // Register header fields
    register_fields();

    // Register preferences
    register_preferences();

    // Register toolbar (must be done during proto_register, not handoff)
    // The toolbar will appear in View -> Toolbars -> Matchy
    register_toolbar();
}

/// Value strings for threat level field (enables filter autocomplete)
/// Must be null-terminated array
static THREAT_LEVEL_VALS: [wireshark_ffi::value_string; 6] = [
    wireshark_ffi::value_string { value: 4, strptr: c"Critical".as_ptr() },
    wireshark_ffi::value_string { value: 3, strptr: c"High".as_ptr() },
    wireshark_ffi::value_string { value: 2, strptr: c"Medium".as_ptr() },
    wireshark_ffi::value_string { value: 1, strptr: c"Low".as_ptr() },
    wireshark_ffi::value_string { value: 0, strptr: c"Unknown".as_ptr() },
    // Null terminator
    wireshark_ffi::value_string { value: 0, strptr: std::ptr::null() },
];

/// Static storage for header field registration info
/// These MUST be static because Wireshark keeps pointers to them
static mut HF_ARRAY: [wireshark_ffi::hf_register_info; 9] = {
    use wireshark_ffi::*;
    [
        hf_register_info {
            p_id: std::ptr::null_mut(), // Will be set at runtime
            hfinfo: header_field_info {
                name: c"Threat Detected".as_ptr(),
                abbrev: c"matchy.threat_detected".as_ptr(),
                type_: FT_BOOLEAN,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Whether this packet matches a threat indicator".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Threat Level".as_ptr(),
                abbrev: c"matchy.level".as_ptr(),
                type_: FT_UINT8,
                display: BASE_DEC,
                // Note: strings pointer is set at runtime in proto_register_matchy
                // because we can't reference THREAT_LEVEL_VALS in const context
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Severity level of the threat".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Category".as_ptr(),
                abbrev: c"matchy.category".as_ptr(),
                type_: FT_STRING,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Type of threat (malware, phishing, c2, etc.)".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Source".as_ptr(),
                abbrev: c"matchy.source".as_ptr(),
                type_: FT_STRING,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Threat intelligence feed source".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Indicator".as_ptr(),
                abbrev: c"matchy.indicator".as_ptr(),
                type_: FT_STRING,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"The matched threat indicator".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Indicator Type".as_ptr(),
                abbrev: c"matchy.indicator_type".as_ptr(),
                type_: FT_STRING,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Type of indicator (ip, domain, url, email, hash)".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        // ThreatDB optional fields
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Confidence".as_ptr(),
                abbrev: c"matchy.confidence".as_ptr(),
                type_: FT_UINT8,
                display: BASE_DEC,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Confidence score (0-100) for this indicator".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"TLP".as_ptr(),
                abbrev: c"matchy.tlp".as_ptr(),
                type_: FT_STRING,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"Traffic Light Protocol marking for information sharing".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
        hf_register_info {
            p_id: std::ptr::null_mut(),
            hfinfo: header_field_info {
                name: c"Last Seen".as_ptr(),
                abbrev: c"matchy.last_seen".as_ptr(),
                type_: FT_STRING,
                display: BASE_NONE,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: c"When the indicator was last observed active".as_ptr(),
                id: -1,
                parent: 0,
                ref_type: 0,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        },
    ]
};

/// Static storage for subtree indices
static mut ETT_ARRAY: [*mut c_int; 1] = [std::ptr::null_mut()];

/// Callback invoked when preferences are updated
/// This is called both at startup (after prefs are read) and when user changes prefs
unsafe extern "C" fn preferences_apply() {
    // Check if a database path was set
    if DATABASE_PATH.is_null() {
        return;
    }

    // Load database from the configured path
    let path = std::ffi::CStr::from_ptr(DATABASE_PATH);
    if let Ok(path_str) = path.to_str() {
        if !path_str.is_empty() {
            if matchy_load_database(DATABASE_PATH) == 0 {
                // Database loaded successfully - force redissection so our
                // threat cache is populated for filter matching
                wireshark_ffi::plugin_if_apply_filter(c"".as_ptr(), true);
            }
        }
    }
}

/// Register preferences for the protocol
unsafe fn register_preferences() {
    use wireshark_ffi::*;

    // Register preferences module for the Matchy protocol
    // This will appear under Edit -> Preferences -> Protocols -> Matchy
    let prefs_module = prefs_register_protocol(PROTO_MATCHY, Some(preferences_apply));

    if prefs_module.is_null() {
        return;
    }

    // Register filename preference for database path
    static DB_NAME: &[u8] = b"database_path\0";
    static DB_TITLE: &[u8] = b"Database Path\0";
    static DB_DESC: &[u8] = b"Path to the .mxy threat database file\0";

    prefs_register_filename_preference(
        prefs_module,
        DB_NAME.as_ptr() as *const c_char,
        DB_TITLE.as_ptr() as *const c_char,
        DB_DESC.as_ptr() as *const c_char,
        std::ptr::addr_of_mut!(DATABASE_PATH),
        0, // for_writing = false (we're reading the database)
    );
}

/// Register header fields for display and filtering
unsafe fn register_fields() {
    use wireshark_ffi::*;

    // Set up the p_id pointers to point to our static field ID variables
    HF_ARRAY[0].p_id = std::ptr::addr_of_mut!(HF_THREAT_DETECTED);
    HF_ARRAY[1].p_id = std::ptr::addr_of_mut!(HF_THREAT_LEVEL);
    HF_ARRAY[2].p_id = std::ptr::addr_of_mut!(HF_THREAT_CATEGORY);
    HF_ARRAY[3].p_id = std::ptr::addr_of_mut!(HF_THREAT_SOURCE);
    HF_ARRAY[4].p_id = std::ptr::addr_of_mut!(HF_THREAT_INDICATOR);
    HF_ARRAY[5].p_id = std::ptr::addr_of_mut!(HF_THREAT_INDICATOR_TYPE);
    // ThreatDB optional fields
    HF_ARRAY[6].p_id = std::ptr::addr_of_mut!(HF_THREAT_CONFIDENCE);
    HF_ARRAY[7].p_id = std::ptr::addr_of_mut!(HF_THREAT_TLP);
    HF_ARRAY[8].p_id = std::ptr::addr_of_mut!(HF_THREAT_LAST_SEEN);

    // Set the value_string pointer for threat level field (enables filter autocomplete)
    // This must be done at runtime because we can't reference static data in const context
    HF_ARRAY[1].hfinfo.strings = THREAT_LEVEL_VALS.as_ptr() as *const libc::c_void;

    proto_register_field_array(PROTO_MATCHY, HF_ARRAY.as_mut_ptr(), HF_ARRAY.len() as c_int);

    // Register subtree
    ETT_ARRAY[0] = std::ptr::addr_of_mut!(ETT_MATCHY);
    proto_register_subtree_array(ETT_ARRAY.as_ptr(), ETT_ARRAY.len() as c_int);
}

// ============================================================================
// Handoff Registration (called by Wireshark after all protocols registered)
// ============================================================================

/// Menu callback for "Reload Matchy Database"
/// This reloads the database from the configured path and triggers a redissection
unsafe extern "C" fn menu_reload_database(
    _gui_type: wireshark_ffi::ext_menubar_gui_type,
    _gui_object: *mut std::ffi::c_void,
    _user_data: *mut std::ffi::c_void,
) {
    // Check if we have a database path configured
    if DATABASE_PATH.is_null() {
        return;
    }

    let path = std::ffi::CStr::from_ptr(DATABASE_PATH);
    if let Ok(path_str) = path.to_str() {
        if path_str.is_empty() {
            return;
        }

        let _ = matchy_load_database(DATABASE_PATH);
        // Force redissection with current filter
        wireshark_ffi::plugin_if_apply_filter(c"".as_ptr(), true);
    }
}

/// Register the Tools menu items
unsafe fn register_menu() {
    use wireshark_ffi::*;

    // Register a menu under Tools
    let menu = ext_menubar_register_menu(
        PROTO_MATCHY,
        c"Matchy".as_ptr(),
        true, // is_plugin
    );

    if menu.is_null() {
        return;
    }

    // Place it under the Tools menu
    ext_menubar_set_parentmenu(menu, c"Tools".as_ptr());

    // Add "Reload Database" entry
    ext_menubar_add_entry(
        menu,
        c"Reload Matchy Database".as_ptr(),
        c"Reload the threat database and redissect all packets".as_ptr(),
        menu_reload_database,
        std::ptr::null_mut(),
    );
}

/// Register the header field IDs we want to access from other protocols.
/// This tells Wireshark to build the protocol tree when these fields are present,
/// which is necessary for our postdissector to work with display filters.
unsafe fn register_wanted_hfids(handle: wireshark_ffi::dissector_handle_t) {
    use wireshark_ffi::*;

    // List of field names we want to access
    // These are the same fields defined in postdissector.rs
    let field_names: &[&str] = &[
        // DNS
        "dns.qry.name",
        "dns.resp.name",
        "dns.cname",
        "dns.mx.mail_exchange",
        "dns.a",
        "dns.aaaa",
        // HTTP
        "http.host",
        "http.request.uri.host",
        "http.request.full_uri",
        "http.request.uri",
        "http.referer",
        "http.location",
        "http.x_forwarded_for",
        "http2.headers.authority",
        "http2.request.full_uri",
        "http2.headers.path",
        // TLS
        "tls.handshake.extensions_server_name",
        "tls.handshake.ja3",
        "tls.handshake.ja3s",
        // X.509
        "x509sat.uTF8String",
        "x509ce.dNSName",
        "x509ce.rfc822Name",
        "x509ce.iPAddress",
        // SIP
        "sip.from.host",
        "sip.to.host",
        // SMTP/Email
        "imf.from",
        "imf.to",
        "smtp.req.parameter",
    ];

    // Create a GArray of hf_ids
    let hfids = g_array_new(0, 0, std::mem::size_of::<c_int>() as libc::c_uint);
    if hfids.is_null() {
        return;
    }

    for field_name in field_names {
        let field_name_c = std::ffi::CString::new(*field_name).unwrap();
        let hf_id = proto_registrar_get_id_byname(field_name_c.as_ptr());
        if hf_id >= 0 {
            g_array_append_vals(hfids, &hf_id as *const c_int as *const libc::c_void, 1);
        }
    }

    // Also add our OWN field IDs - this tells Wireshark that when filtering
    // on matchy.* fields, it needs to build the tree
    let our_fields: &[c_int] = &[
        HF_THREAT_DETECTED,
        HF_THREAT_LEVEL,
        HF_THREAT_CATEGORY,
        HF_THREAT_SOURCE,
        HF_THREAT_INDICATOR,
        HF_THREAT_INDICATOR_TYPE,
        HF_THREAT_CONFIDENCE,
        HF_THREAT_TLP,
        HF_THREAT_LAST_SEEN,
    ];
    for &hf_id in our_fields {
        if hf_id >= 0 {
            g_array_append_vals(hfids, &hf_id as *const c_int as *const libc::c_void, 1);
        }
    }

    // Tell Wireshark we want these fields
    set_postdissector_wanted_hfids(handle, hfids);
    // Note: Wireshark takes ownership of the GArray, don't free it
}

/// Toolbar button callback for reload (used by both status button and reload button)
unsafe extern "C" fn toolbar_reload_callback(
    _toolbar_item: *mut std::ffi::c_void,
    _item_data: *mut std::ffi::c_void,
    _user_data: *mut std::ffi::c_void,
) {
    // Reuse the same logic as the menu callback
    if DATABASE_PATH.is_null() {
        return;
    }

    let path = std::ffi::CStr::from_ptr(DATABASE_PATH);
    if let Ok(path_str) = path.to_str() {
        if path_str.is_empty() {
            return;
        }

        let _ = matchy_load_database(DATABASE_PATH);
        // Force redissection with current filter
        wireshark_ffi::plugin_if_apply_filter(c"".as_ptr(), true);
    }
}

/// Register the Matchy toolbar
/// Creates a toolbar with database status display and reload button
unsafe fn register_toolbar() {
    use wireshark_ffi::*;

    // Register the toolbar - will appear in View -> Toolbars -> Matchy
    let toolbar = ext_toolbar_register_toolbar(c"Matchy".as_ptr());

    if toolbar.is_null() {
        return;
    }

    // Single button that shows database status and reloads when clicked
    // Button text is updated dynamically via update_toolbar_status()
    // Format: "Matchy" initially, then "Matchy: filename.mxy (stats)" once UI is ready
    let reload_entry = ext_toolbar_add_entry(
        toolbar,
        ext_toolbar_item_t::EXT_TOOLBAR_BUTTON,
        c"Matchy".as_ptr(),                 // label (initial text, updated dynamically)
        std::ptr::null(),                   // default value (not used for BUTTON)
        c"Reload the Matchy threat database (configure path in Preferences > Protocols > Matchy)".as_ptr(),
        false,                              // capture_only
        std::ptr::null_mut(),               // value_list
        false,                              // is_required
        std::ptr::null(),                   // valid_regex
        Some(toolbar_reload_callback),      // callback
        std::ptr::null_mut(),               // user_data
    );

    // Store the entry handle for later updates
    TOOLBAR_STATUS_ENTRY = reload_entry;
}

/// Update the toolbar status display with current database info
/// If called before the UI is ready, sets a flag to update later
unsafe fn update_toolbar_status() {
    use wireshark_ffi::*;

    if TOOLBAR_STATUS_ENTRY.is_null() {
        return;
    }

    let status_text = if let Ok(guard) = THREAT_DB.lock() {
        if let Some(ref db) = *guard {
            // Get counts from the database
            let ip_count = db.ip_count();
            let literal_count = db.literal_count();
            let glob_count = db.glob_count();

            // Get filename from path
            let filename = if !DATABASE_PATH.is_null() {
                if let Ok(path_str) = CStr::from_ptr(DATABASE_PATH).to_str() {
                    std::path::Path::new(path_str)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("database")
                } else {
                    "database"
                }
            } else {
                "database"
            };

            // Format counts with K/M suffixes for readability
            let format_count = |n: usize| -> String {
                if n >= 1_000_000 {
                    format!("{:.1}M", n as f64 / 1_000_000.0)
                } else if n >= 1_000 {
                    format!("{:.1}K", n as f64 / 1_000.0)
                } else {
                    format!("{}", n)
                }
            };

            // Build status string with non-zero counts
            let mut parts = Vec::new();
            if ip_count > 0 {
                parts.push(format!("{} IPs", format_count(ip_count)));
            }
            if literal_count > 0 {
                parts.push(format!("{} strings", format_count(literal_count)));
            }
            if glob_count > 0 {
                parts.push(format!("{} patterns", format_count(glob_count)));
            }

            if parts.is_empty() {
                format!("Matchy: {} (empty)", filename)
            } else {
                format!("Matchy: {} ({})", filename, parts.join(", "))
            }
        } else {
            "Matchy: No database".to_string()
        }
    } else {
        "Matchy: No database".to_string()
    };

    // Update the toolbar entry
    let status_c = std::ffi::CString::new(status_text).unwrap_or_default();
    ext_toolbar_update_value(
        TOOLBAR_STATUS_ENTRY,
        status_c.as_ptr() as *mut std::ffi::c_void,
        true, // silent - don't trigger callback
    );

    // Also set the flag so we can retry later if the widget wasn't ready
    TOOLBAR_NEEDS_UPDATE = true;
}

/// Try to update the toolbar if we have a pending update
/// Called from dissector when we know the UI is ready
pub(crate) unsafe fn try_pending_toolbar_update() {
    if TOOLBAR_NEEDS_UPDATE {
        TOOLBAR_NEEDS_UPDATE = false;
        update_toolbar_status();
    }
}

/// Called by Wireshark to register our postdissector
/// This is called after all protocols are registered, so we can safely
/// create our dissector handle and register it.
#[no_mangle]
unsafe extern "C" fn proto_reg_handoff_matchy() {
    use wireshark_ffi::*;

    // Create dissector handle first
    let handle = create_dissector_handle(postdissector::dissect_matchy, PROTO_MATCHY);
    
    // Store handle for use in final registration callback
    DISSECTOR_HANDLE = handle;

    // Register a callback for after ALL protocols have registered their fields.
    // This sets up the wanted hfids BEFORE we're active as a postdissector
    register_final_registration_routine(final_registration_callback);

    // NOW register as postdissector (after setting up the callback)
    register_postdissector(handle);

    // Register Tools menu
    register_menu();

    // Try to load database from environment variable
    if let Ok(db_path) = std::env::var("MATCHY_DATABASE") {
        let path_c = std::ffi::CString::new(db_path).unwrap();
        let _ = matchy_load_database(path_c.as_ptr());
    }
    // Note: Database from preferences is loaded via preferences_apply() callback
    // which is called after this. The toolbar update will be deferred until
    // the first packet dissection when the UI is ready.
}

/// Called after ALL protocols have registered their fields.
/// This is the right time to look up hfids from other protocols.
unsafe extern "C" fn final_registration_callback() {
    if !DISSECTOR_HANDLE.is_null() {
        register_wanted_hfids(DISSECTOR_HANDLE);
    }
}

// ============================================================================
// Public API for database management
// ============================================================================

/// Load a matchy threat database
///
/// # Safety
/// Caller must ensure `path` is a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn matchy_load_database(path: *const c_char) -> c_int {
    if path.is_null() {
        return -1;
    }

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // IMPORTANT: Drop the old database BEFORE opening the new one.
    // The matchy library uses mmap, and opening a new file at the same path
    // while the old mmap is still active can result in stale cached data.
    let _had_old = if let Ok(mut guard) = THREAT_DB.lock() {
        let existed = guard.is_some();
        *guard = None; // Drop the old database, releasing the mmap
        existed
    } else {
        return -1;
    };

    match matchy::Database::from(path_str).open() {
        Ok(db) => {
            if let Ok(mut guard) = THREAT_DB.lock() {
                *guard = Some(db);
                drop(guard); // Release lock before updating toolbar
                update_toolbar_status();
                0
            } else {
                -1
            }
        }
        Err(_) => {
            update_toolbar_status(); // Update to show "no database" or error
            -1
        }
    }
}

/// Check if a database is loaded
#[no_mangle]
pub extern "C" fn matchy_database_loaded() -> c_int {
    match THREAT_DB.lock() {
        Ok(guard) => {
            if guard.is_some() {
                1
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

/// Unload the current database
#[no_mangle]
pub extern "C" fn matchy_unload_database() {
    if let Ok(mut guard) = THREAT_DB.lock() {
        *guard = None;
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

pub(crate) fn get_database() -> Option<std::sync::MutexGuard<'static, Option<matchy::Database>>> {
    THREAT_DB.lock().ok()
}

/// Header field IDs for the postdissector
pub(crate) struct HfIds {
    pub detected: c_int,
    pub level: c_int,
    pub category: c_int,
    pub source: c_int,
    pub indicator: c_int,
    pub indicator_type: c_int,
    // ThreatDB optional fields
    pub confidence: c_int,
    pub tlp: c_int,
    pub last_seen: c_int,
}

pub(crate) fn get_hf_ids() -> HfIds {
    unsafe {
        HfIds {
            detected: HF_THREAT_DETECTED,
            level: HF_THREAT_LEVEL,
            category: HF_THREAT_CATEGORY,
            source: HF_THREAT_SOURCE,
            indicator: HF_THREAT_INDICATOR,
            indicator_type: HF_THREAT_INDICATOR_TYPE,
            confidence: HF_THREAT_CONFIDENCE,
            tlp: HF_THREAT_TLP,
            last_seen: HF_THREAT_LAST_SEEN,
        }
    }
}

pub(crate) fn get_ett_matchy() -> c_int {
    unsafe { ETT_MATCHY }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_version() {
        // Version should be null-terminated
        let last = plugin_version[plugin_version.len() - 1];
        assert_eq!(last, 0, "plugin_version must be null-terminated");

        // Version should match Cargo.toml
        let version_str = std::ffi::CStr::from_bytes_until_nul(unsafe {
            std::slice::from_raw_parts(plugin_version.as_ptr() as *const u8, plugin_version.len())
        })
        .unwrap()
        .to_str()
        .unwrap();
        assert_eq!(version_str, env!("CARGO_PKG_VERSION"));
    }
}
