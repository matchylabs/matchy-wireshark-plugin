//! Wireshark postdissector implementation
//!
//! A postdissector runs after normal dissection, allowing us to add
//! custom fields based on threat intelligence lookups.
//!
//! Supports lookups on:
//! - IP addresses (source and destination)
//! - DNS query names
//! - HTTP Host headers
//! - TLS SNI (Server Name Indication)
//! - TLS certificate hostnames

use crate::threats::ThreatData;
use crate::wireshark_ffi::*;
use libc::c_int;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Fields to extract for domain/hostname intelligence matching
const DOMAIN_FIELDS: &[&str] = &[
    // DNS
    "dns.qry.name",      // DNS query name
    "dns.resp.name",     // DNS response name
    "dns.cname",         // CNAME records
    "dns.mx.mail_exchange", // MX records
    // HTTP
    "http.host",         // HTTP Host header
    "http.request.uri.host", // HTTP/2 :authority or host from URL
    // TLS/SSL
    "tls.handshake.extensions_server_name", // TLS SNI
    // X.509 certificates (TLS)
    "x509sat.uTF8String", // Certificate CN/SAN (UTF8String)
    "x509sat.printableString", // Certificate CN/SAN (PrintableString)
    "x509ce.dNSName",    // Certificate SAN dNSName
];

/// Fields to extract for URL/path intelligence matching
const URL_FIELDS: &[&str] = &[
    "http.request.full_uri", // Full HTTP request URI
    "http.request.uri",      // HTTP request path (without host)
    "http.response_for.uri", // URI that this response is for
];

/// Postdissector callback - processes each packet
/// This is called by Wireshark after normal dissection.
///
/// # Safety
/// This function is called from C code.
#[no_mangle]
pub unsafe extern "C" fn dissect_matchy(
    tvb: *mut tvbuff_t,
    pinfo: *mut packet_info,
    tree: *mut proto_tree,
    _data: *mut libc::c_void,
) -> c_int {
    // Safety checks
    if tvb.is_null() || pinfo.is_null() {
        return 0;
    }

    // Get the database - if not loaded, nothing to do
    let db_guard = match crate::get_database() {
        Some(guard) => guard,
        None => return 0,
    };

    let db = match db_guard.as_ref() {
        Some(db) => db,
        None => {
            // No database loaded - silent return
            return 0;
        }
    };

    // Track indicators we've already matched to avoid duplicates
    let mut matched_indicators: HashSet<String> = HashSet::new();

    // Extract source and destination IPs from packet_info
    let src_addr = pinfo_get_src(pinfo);
    let dst_addr = pinfo_get_dst(pinfo);

    // Try to get IPv4/IPv6 addresses
    let src_ip = extract_ip(src_addr);
    let dst_ip = extract_ip(dst_addr);

    // Check source IP
    if let Some(ip) = src_ip {
        let indicator = ip.to_string();
        if !matched_indicators.contains(&indicator) {
            if let Some(threat) = lookup_ip(db, &ip) {
                if !tree.is_null() {
                    add_threat_to_tree(tree, tvb, &indicator, "ip", &threat);
                }
                matched_indicators.insert(indicator);
            }
        }
    }

    // Check destination IP
    if let Some(ip) = dst_ip {
        let indicator = ip.to_string();
        if !matched_indicators.contains(&indicator) {
            if let Some(threat) = lookup_ip(db, &ip) {
                if !tree.is_null() {
                    add_threat_to_tree(tree, tvb, &indicator, "ip", &threat);
                }
                matched_indicators.insert(indicator);
            }
        }
    }

    // Extract and check domain/hostname fields from protocol tree
    if !tree.is_null() {
        for field_name in DOMAIN_FIELDS {
            let domains = extract_string_fields(tree, field_name);
            for domain in domains {
                // Normalize: lowercase and strip trailing dot (DNS FQDN)
                let normalized = domain.trim_end_matches('.').to_lowercase();
                if normalized.is_empty() || matched_indicators.contains(&normalized) {
                    continue;
                }

                if let Some(threat) = lookup_domain(db, &normalized) {
                    add_threat_to_tree(tree, tvb, &normalized, "domain", &threat);
                    matched_indicators.insert(normalized);
                }
            }
        }

        // Extract and check URL fields
        for field_name in URL_FIELDS {
            let urls = extract_string_fields(tree, field_name);
            for url in urls {
                if url.is_empty() || matched_indicators.contains(&url) {
                    continue;
                }

                // Try to match the full URL
                if let Some(threat) = lookup_domain(db, &url) {
                    add_threat_to_tree(tree, tvb, &url, "url", &threat);
                    matched_indicators.insert(url);
                }
            }
        }
    }

    // Return number of bytes consumed (0 = we're a postdissector, don't consume)
    0
}

/// Extract IP address from Wireshark address struct
unsafe fn extract_ip(addr: *const address) -> Option<IpAddr> {
    if let Some(ipv4_bytes) = address_to_ipv4(addr) {
        return Some(IpAddr::V4(Ipv4Addr::from(ipv4_bytes)));
    }
    if let Some(ipv6_bytes) = address_to_ipv6(addr) {
        return Some(IpAddr::V6(Ipv6Addr::from(ipv6_bytes)));
    }
    None
}

/// Look up an IP in the threat database
///
/// Returns parsed ThreatData if a match is found.
unsafe fn lookup_ip(db: &matchy::Database, ip: &IpAddr) -> Option<ThreatData> {
    if let Ok(Some(matchy::QueryResult::Ip { data, .. })) = db.lookup_ip(*ip) {
        let json = data_value_to_json(&data);
        return ThreatData::from_json(&json);
    }
    None
}

/// Look up a domain/hostname in the threat database
///
/// Returns parsed ThreatData if a match is found.
/// Supports both exact matches and glob patterns (e.g., *.evil.com)
fn lookup_domain(db: &matchy::Database, domain: &str) -> Option<ThreatData> {
    // Use lookup_string which checks both literal hash and glob patterns
    if let Ok(Some(matchy::QueryResult::Pattern { data, .. })) = db.lookup_string(domain) {
        // Get the first match's data (most specific match)
        if let Some(Some(data_value)) = data.first() {
            let json = data_value_to_json(data_value);
            return ThreatData::from_json(&json);
        }
    }
    None
}

/// Convert matchy DataValue to serde_json Value
fn data_value_to_json(data: &matchy_data_format::DataValue) -> serde_json::Value {
    use matchy_data_format::DataValue;

    match data {
        DataValue::Map(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                obj.insert(k.clone(), data_value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        DataValue::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(data_value_to_json).collect())
        }
        DataValue::String(s) => serde_json::Value::String(s.clone()),
        DataValue::Bytes(b) => serde_json::Value::String(format!("{:?}", b)),
        DataValue::Uint16(n) => serde_json::Value::Number((*n).into()),
        DataValue::Uint32(n) => serde_json::Value::Number((*n).into()),
        DataValue::Uint64(n) => serde_json::Value::Number((*n).into()),
        DataValue::Uint128(n) => serde_json::Value::String(n.to_string()),
        DataValue::Int32(n) => serde_json::Value::Number((*n).into()),
        DataValue::Float(f) => {
            serde_json::Value::Number(serde_json::Number::from_f64(*f as f64).unwrap_or(0.into()))
        }
        DataValue::Double(f) => {
            serde_json::Value::Number(serde_json::Number::from_f64(*f).unwrap_or(0.into()))
        }
        DataValue::Bool(b) => serde_json::Value::Bool(*b),
        DataValue::Pointer(_) => serde_json::Value::Null, // Internal use only
    }
}

/// Add threat information to the protocol tree
///
/// # Arguments
/// * `indicator` - The matched indicator value (IP, domain, etc.)
/// * `indicator_type` - The type of indicator ("ip" or "domain")
unsafe fn add_threat_to_tree(
    tree: *mut proto_tree,
    tvb: *mut tvbuff_t,
    indicator: &str,
    indicator_type: &str,
    threat: &ThreatData,
) {
    let (hf_detected, hf_level, hf_category, hf_source, hf_indicator, hf_indicator_type) =
        crate::get_hf_ids();
    let ett = crate::get_ett_matchy();

    // Add the Matchy subtree
    let ti = proto_tree_add_boolean(
        tree,
        hf_detected,
        tvb,
        0,
        0,
        1, // true - threat detected
    );

    if ti.is_null() {
        return;
    }

    let subtree = proto_item_add_subtree(ti, ett);
    if subtree.is_null() {
        return;
    }

    // Add threat details (Wireshark copies string values for FT_STRINGZ)
    let level_str = to_c_string(threat.level.display_str());
    proto_tree_add_string(subtree, hf_level, tvb, 0, 0, level_str.as_ptr());

    let category_str = to_c_string(&threat.category);
    proto_tree_add_string(subtree, hf_category, tvb, 0, 0, category_str.as_ptr());

    let source_str = to_c_string(&threat.source);
    proto_tree_add_string(subtree, hf_source, tvb, 0, 0, source_str.as_ptr());

    let indicator_str = to_c_string(indicator);
    proto_tree_add_string(subtree, hf_indicator, tvb, 0, 0, indicator_str.as_ptr());

    let indicator_type_str = to_c_string(indicator_type);
    proto_tree_add_string(subtree, hf_indicator_type, tvb, 0, 0, indicator_type_str.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_extraction() {
        // Test that our IP parsing works
        let ipv4 = Ipv4Addr::new(192, 168, 1, 1);
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        assert_eq!(ipv4.to_string(), "192.168.1.1");
        assert_eq!(ipv6.to_string(), "2001:db8::1");
    }
}
