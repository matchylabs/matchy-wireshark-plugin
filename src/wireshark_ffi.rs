//! FFI bindings for Wireshark C API
//!
//! This module contains only the types and functions needed for postdissector
//! implementation. We keep this minimal and focused.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use libc::{c_char, c_int, c_uint, c_void};
use std::ptr;

// ============================================================================
// Core Opaque Types
// ============================================================================

/// Wireshark protocol handle
#[repr(C)]
pub struct proto_t {
    _private: [u8; 0],
}

/// Wireshark header field info
#[repr(C)]
pub struct hf_register_info_t {
    _private: [u8; 0],
}

/// Packet info structure (contains source/dest addresses, ports, etc.)
#[repr(C)]
pub struct packet_info {
    _private: [u8; 0],
}

/// Tree Value Buffer - contains raw packet data
#[repr(C)]
pub struct tvbuff_t {
    _private: [u8; 0],
}

/// Protocol tree node - hierarchical display structure
#[repr(C)]
pub struct proto_tree {
    _private: [u8; 0],
}

/// Protocol item (a single field in the tree)
#[repr(C)]
pub struct proto_item {
    _private: [u8; 0],
}

/// Dissector handle
#[repr(C)]
pub struct dissector_handle_t {
    _private: [u8; 0],
}

/// Dissector table
#[repr(C)]
pub struct dissector_table_t {
    _private: [u8; 0],
}

// ============================================================================
// Field Types and Display
// ============================================================================

/// Field type enumeration
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum ftenum {
    FT_NONE = 0,
    FT_BOOLEAN = 1,
    FT_UINT8 = 2,
    FT_UINT16 = 3,
    FT_UINT24 = 4,
    FT_UINT32 = 5,
    FT_UINT64 = 6,
    FT_INT8 = 7,
    FT_INT16 = 8,
    FT_INT24 = 9,
    FT_INT32 = 10,
    FT_INT64 = 11,
    FT_STRING = 12,
    FT_STRINGZ = 13,
    FT_BYTES = 14,
    FT_IPv4 = 15,
    FT_IPv6 = 16,
}

/// Field display format
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum field_display_e {
    BASE_NONE = 0,
    BASE_DEC = 1,
    BASE_HEX = 2,
    BASE_OCT = 3,
    BASE_DEC_HEX = 4,
    BASE_HEX_DEC = 5,
}

// ============================================================================
// Postdissector Registration
// ============================================================================

/// Postdissector function signature
pub type postdissector_fn = unsafe extern "C" fn(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    data: *mut c_void,
) -> c_int;

// ============================================================================
// External Functions (linked from Wireshark)
// ============================================================================

extern "C" {
    // Protocol registration
    pub fn proto_register_protocol(
        name: *const c_char,
        short_name: *const c_char,
        filter_name: *const c_char,
    ) -> c_int;

    pub fn proto_register_field_array(
        proto: c_int,
        hf: *mut c_int,
        num_records: c_int,
    );

    pub fn proto_register_subtree_array(
        indices: *mut *mut c_int,
        num_indices: c_int,
    );

    // Postdissector registration
    pub fn register_postdissector(handle: *mut dissector_handle_t);

    pub fn create_dissector_handle(
        func: postdissector_fn,
        proto: c_int,
    ) -> *mut dissector_handle_t;

    // Tree manipulation
    pub fn proto_tree_add_item(
        tree: *mut proto_tree,
        hf_index: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        encoding: c_uint,
    ) -> *mut proto_item;

    pub fn proto_tree_add_string(
        tree: *mut proto_tree,
        hf_index: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: *const c_char,
    ) -> *mut proto_item;

    pub fn proto_tree_add_boolean(
        tree: *mut proto_tree,
        hf_index: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: c_uint,
    ) -> *mut proto_item;

    pub fn proto_item_add_subtree(
        item: *mut proto_item,
        idx: c_int,
    ) -> *mut proto_tree;

    // Packet coloring
    pub fn expert_add_info(
        pinfo: *mut packet_info,
        item: *mut proto_item,
        expert_info: *const c_void,
    );

    // Packet info accessors
    pub fn tvb_reported_length(tvb: *mut tvbuff_t) -> c_uint;
    pub fn tvb_captured_length(tvb: *mut tvbuff_t) -> c_uint;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Register a protocol with Wireshark
pub unsafe fn register_protocol(
    name: &str,
    short_name: &str,
    filter_name: &str,
) -> c_int {
    let name_c = std::ffi::CString::new(name).unwrap();
    let short_c = std::ffi::CString::new(short_name).unwrap();
    let filter_c = std::ffi::CString::new(filter_name).unwrap();
    
    proto_register_protocol(
        name_c.as_ptr(),
        short_c.as_ptr(),
        filter_c.as_ptr(),
    )
}

/// Register a postdissector callback
pub unsafe fn register_postdissector_callback(
    func: postdissector_fn,
    proto_id: c_int,
) {
    let handle = create_dissector_handle(func, proto_id);
    register_postdissector(handle);
}

/// Add a string field to the packet tree
pub unsafe fn add_string_field(
    tree: *mut proto_tree,
    hf_index: c_int,
    tvb: *mut tvbuff_t,
    value: &str,
) -> *mut proto_item {
    let value_c = std::ffi::CString::new(value).unwrap();
    proto_tree_add_string(
        tree,
        hf_index,
        tvb,
        0,
        0,
        value_c.as_ptr(),
    )
}

/// Add a boolean field to the packet tree
pub unsafe fn add_boolean_field(
    tree: *mut proto_tree,
    hf_index: c_int,
    tvb: *mut tvbuff_t,
    value: bool,
) -> *mut proto_item {
    proto_tree_add_boolean(
        tree,
        hf_index,
        tvb,
        0,
        0,
        if value { 1 } else { 0 },
    )
}

// ============================================================================
// Constants
// ============================================================================

/// Encoding for little-endian integers
pub const ENC_LITTLE_ENDIAN: c_uint = 0x80000000;

/// Encoding for big-endian integers
pub const ENC_BIG_ENDIAN: c_uint = 0x00000000;

/// String encoding UTF-8
pub const ENC_UTF_8: c_uint = 0x00000002;

/// Return value for dissector functions (packet was dissected)
pub const DISSECTOR_OK: c_int = 1;

// ============================================================================
// Header Field Registration
// ============================================================================

/// Header field registration structure (simplified)
#[repr(C)]
pub struct HeaderField {
    pub hf_id: *mut c_int,
    pub name: *const c_char,
    pub abbrev: *const c_char,
    pub field_type: ftenum,
    pub display: field_display_e,
    pub strings: *const c_void,
    pub bitmask: c_uint,
    pub blurb: *const c_char,
}

impl HeaderField {
    /// Create a new string header field
    pub fn string(
        hf_id: &mut c_int,
        name: &'static str,
        abbrev: &'static str,
        blurb: &'static str,
    ) -> Self {
        HeaderField {
            hf_id: hf_id as *mut c_int,
            name: name.as_ptr() as *const c_char,
            abbrev: abbrev.as_ptr() as *const c_char,
            field_type: ftenum::FT_STRING,
            display: field_display_e::BASE_NONE,
            strings: ptr::null(),
            bitmask: 0,
            blurb: blurb.as_ptr() as *const c_char,
        }
    }

    /// Create a new boolean header field
    pub fn boolean(
        hf_id: &mut c_int,
        name: &'static str,
        abbrev: &'static str,
        blurb: &'static str,
    ) -> Self {
        HeaderField {
            hf_id: hf_id as *mut c_int,
            name: name.as_ptr() as *const c_char,
            abbrev: abbrev.as_ptr() as *const c_char,
            field_type: ftenum::FT_BOOLEAN,
            display: field_display_e::BASE_NONE,
            strings: ptr::null(),
            bitmask: 0,
            blurb: blurb.as_ptr() as *const c_char,
        }
    }
}
