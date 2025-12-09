//! Wireshark postdissector implementation
//!
//! A postdissector runs after normal dissection, allowing us to add
//! custom fields based on threat intelligence lookups.
//!
//! ## Supported Indicator Types
//!
//! ### IP Addresses (`indicator_type = "ip"`)
//! - Source/destination IPs from packet headers
//! - DNS A/AAAA record responses
//! - HTTP X-Forwarded-For headers
//! - X.509 certificate IP SANs
//! - EDNS Client Subnet IPs
//!
//! ### Domain Names (`indicator_type = "domain"`)
//! - DNS queries and responses (qry.name, resp.name, CNAME, MX)
//! - HTTP/HTTP2 Host headers and authority
//! - TLS SNI (Server Name Indication)
//! - X.509 certificate CN and DNS SANs
//! - SIP headers (From, To, Contact, Via hosts)
//! - Kerberos realms
//! - LDAP/Active Directory domains and hostnames
//! - NetBIOS names (NBNS)
//! - DHCP client hostnames
//! - XMPP/Jabber JIDs
//!
//! ### URLs (`indicator_type = "url"`)
//! - HTTP request URIs (full and path)
//! - HTTP Referer and Location headers
//! - HTTP/2 paths and URIs
//! - X.509 certificate URI SANs
//!
//! ### Email Addresses (`indicator_type = "email"`)
//! - IMF headers (From, To, CC, BCC, Reply-To, Sender)
//! - SMTP parameters (MAIL FROM, RCPT TO)
//! - SIP URI user parts
//! - X.509 certificate email SANs (rfc822Name)
//!
//! ### Hashes/Fingerprints (`indicator_type = "hash"`)
//! - TLS JA3/JA3S fingerprints
//! - SSH host keys

use crate::threats::ThreatData;
use crate::wireshark_ffi::*;
use libc::c_int;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Fields to extract for domain/hostname intelligence matching
const DOMAIN_FIELDS: &[&str] = &[
    // DNS
    "dns.qry.name",         // DNS query name
    "dns.resp.name",        // DNS response name
    "dns.cname",            // CNAME records
    "dns.mx.mail_exchange", // MX records
    // HTTP
    "http.host",               // HTTP Host header
    "http.request.uri.host",   // HTTP/2 :authority or host from URL
    "http2.headers.authority", // HTTP/2 :authority pseudo-header
    // TLS/SSL
    "tls.handshake.extensions_server_name", // TLS SNI
    // X.509 certificates (TLS)
    "x509sat.uTF8String",      // Certificate CN/SAN (UTF8String)
    "x509sat.printableString", // Certificate CN/SAN (PrintableString)
    "x509ce.dNSName",          // Certificate SAN dNSName
    // SIP/VoIP
    "sip.from.host",        // SIP From header host
    "sip.to.host",          // SIP To header host
    "sip.contact.host",     // SIP Contact header host
    "sip.r-uri.host",       // SIP Request-URI host
    "sip.Via.sent-by.address", // SIP Via sent-by address
    // Kerberos
    "kerberos.realm",       // Kerberos realm (domain)
    "kerberos.crealm",      // Client realm
    "kerberos.srealm",      // Server realm
    // LDAP/Active Directory
    "mscldap.hostname",     // MS CLDAP hostname
    "mscldap.domain",       // MS CLDAP domain
    "mscldap.forest",       // MS CLDAP forest
    "mscldap.nb_domain",    // NetBIOS domain
    "mscldap.nb_hostname",  // NetBIOS hostname
    "ldap.baseObject",      // LDAP base DN
    // NetBIOS
    "nbns.name",            // NetBIOS name
    // DHCP
    "dhcp.option.hostname", // DHCP client hostname
    // XMPP/Jabber (domain part of JID)
    "xmpp.to",              // Destination JID
    "xmpp.from",            // Source JID
];

/// Fields to extract for URL/path intelligence matching
const URL_FIELDS: &[&str] = &[
    // HTTP/1.x
    "http.request.full_uri", // Full HTTP request URI
    "http.request.uri",      // HTTP request path (without host)
    "http.response_for.uri", // URI that this response is for
    "http.referer",          // Referer header (can contain full URLs)
    "http.location",         // Location header (redirects)
    // HTTP/2
    "http2.request.full_uri", // HTTP/2 full request URI
    "http2.headers.referer",  // HTTP/2 Referer header
    "http2.headers.location", // HTTP/2 Location header
    "http2.headers.path",     // HTTP/2 :path pseudo-header
    // X.509 certificates
    "x509ce.uniformResourceIdentifier", // URI in certificate SAN
];

/// Fields to extract for email address intelligence matching
const EMAIL_FIELDS: &[&str] = &[
    // IMF (Internet Message Format - parsed email headers)
    "imf.from",        // From header
    "imf.to",          // To header
    "imf.cc",          // CC header
    "imf.bcc",         // BCC header
    "imf.reply_to",    // Reply-To header
    "imf.sender",      // Sender header
    "imf.delivered_to", // Delivered-To header
    // SMTP
    "smtp.req.parameter", // MAIL FROM/RCPT TO parameters
    "smtp.auth.username", // SMTP auth username (often email)
    // SIP (user part of SIP URIs)
    "sip.from.user",    // User from SIP From URI
    "sip.to.user",      // User from SIP To URI
    "sip.contact.user", // User from SIP Contact URI
    // X.509 certificates
    "x509ce.rfc822Name", // Email in certificate SAN
];

/// Fields to extract for IP address intelligence matching (beyond src/dst)
const IP_FIELDS: &[&str] = &[
    // DNS response records
    "dns.a",    // A record (IPv4)
    "dns.aaaa", // AAAA record (IPv6)
    // HTTP headers with IPs
    "http.x_forwarded_for", // X-Forwarded-For (proxy chain)
    // X.509 certificates
    "x509ce.iPAddress", // IP in certificate SAN
    // EDNS Client Subnet
    "dns.opt.client.addr4", // EDNS Client Subnet IPv4
    "dns.opt.client.addr6", // EDNS Client Subnet IPv6
];

/// Fields to extract for hash/fingerprint intelligence matching
const HASH_FIELDS: &[&str] = &[
    // TLS/JA3 fingerprints
    "tls.handshake.ja3",      // JA3 client fingerprint (MD5)
    "tls.handshake.ja3_full", // JA3 full string
    "tls.handshake.ja3s",     // JA3S server fingerprint (MD5)
    "tls.handshake.ja3s_full", // JA3S full string
    // SSH
    "ssh.host_key.data", // SSH host key (can be hashed)
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

                if let Some(threat) = lookup_string(db, &normalized) {
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

                if let Some(threat) = lookup_string(db, &url) {
                    add_threat_to_tree(tree, tvb, &url, "url", &threat);
                    matched_indicators.insert(url);
                }
            }
        }

        // Extract and check email address fields
        for field_name in EMAIL_FIELDS {
            let emails = extract_string_fields(tree, field_name);
            for email in emails {
                let normalized = email.to_lowercase();
                if normalized.is_empty() || matched_indicators.contains(&normalized) {
                    continue;
                }

                if let Some(threat) = lookup_string(db, &normalized) {
                    add_threat_to_tree(tree, tvb, &normalized, "email", &threat);
                    matched_indicators.insert(normalized);
                }
            }
        }

        // Extract and check IP address fields (from DNS responses, headers, etc.)
        for field_name in IP_FIELDS {
            let ip_strings = extract_string_fields(tree, field_name);
            for ip_str in ip_strings {
                if ip_str.is_empty() || matched_indicators.contains(&ip_str) {
                    continue;
                }

                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if let Some(threat) = lookup_ip(db, &ip) {
                        add_threat_to_tree(tree, tvb, &ip_str, "ip", &threat);
                        matched_indicators.insert(ip_str);
                    }
                }
            }
        }

        // Extract and check hash/fingerprint fields
        for field_name in HASH_FIELDS {
            let hashes = extract_string_fields(tree, field_name);
            for hash in hashes {
                let normalized = hash.to_lowercase();
                if normalized.is_empty() || matched_indicators.contains(&normalized) {
                    continue;
                }

                if let Some(threat) = lookup_string(db, &normalized) {
                    add_threat_to_tree(tree, tvb, &normalized, "hash", &threat);
                    matched_indicators.insert(normalized);
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

/// Look up an IP in the threat database and return parsed ThreatData if found.
fn lookup_ip(db: &matchy::Database, ip: &IpAddr) -> Option<ThreatData> {
    if let Ok(Some(matchy::QueryResult::Ip { data, .. })) = db.lookup_ip(*ip) {
        let json = data_value_to_json(&data);
        return ThreatData::from_json(&json);
    }
    None
}

/// Look up a string in the threat database and return parsed ThreatData if found.
fn lookup_string(db: &matchy::Database, value: &str) -> Option<ThreatData> {
    if let Ok(Some(matchy::QueryResult::Pattern { data, .. })) = db.lookup_string(value) {
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
/// * `indicator_type` - The type of indicator ("ip", "domain", "url", "email", "hash")
unsafe fn add_threat_to_tree(
    tree: *mut proto_tree,
    tvb: *mut tvbuff_t,
    indicator: &str,
    indicator_type: &str,
    threat: &ThreatData,
) {
    let hf = crate::get_hf_ids();
    let ett = crate::get_ett_matchy();

    // Add the Matchy subtree
    let ti = proto_tree_add_boolean(
        tree,
        hf.detected,
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
    proto_tree_add_string(subtree, hf.level, tvb, 0, 0, level_str.as_ptr());

    let category_str = to_c_string(&threat.category);
    proto_tree_add_string(subtree, hf.category, tvb, 0, 0, category_str.as_ptr());

    let source_str = to_c_string(&threat.source);
    proto_tree_add_string(subtree, hf.source, tvb, 0, 0, source_str.as_ptr());

    let indicator_str = to_c_string(indicator);
    proto_tree_add_string(subtree, hf.indicator, tvb, 0, 0, indicator_str.as_ptr());

    let indicator_type_str = to_c_string(indicator_type);
    proto_tree_add_string(subtree, hf.indicator_type, tvb, 0, 0, indicator_type_str.as_ptr());

    // ThreatDB optional fields - only display if present
    if let Some(confidence) = threat.confidence {
        proto_tree_add_uint(subtree, hf.confidence, tvb, 0, 0, confidence as libc::c_uint);
    }

    if let Some(ref tlp) = threat.tlp {
        let tlp_str = to_c_string(tlp);
        proto_tree_add_string(subtree, hf.tlp, tvb, 0, 0, tlp_str.as_ptr());
    }

    if let Some(ref last_seen) = threat.last_seen {
        let last_seen_str = to_c_string(last_seen);
        proto_tree_add_string(subtree, hf.last_seen, tvb, 0, 0, last_seen_str.as_ptr());
    }
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
