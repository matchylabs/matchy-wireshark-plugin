//! Threat matching and packet colorization
//!
//! Handles IP/domain lookups and visual threat indicators.

/// Threat level representation
/// Integer values are used for Wireshark field encoding (enables autocomplete)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThreatLevel {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Unknown = 0,
}

impl ThreatLevel {
    /// Convert string to ThreatLevel
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => ThreatLevel::Critical,
            "high" => ThreatLevel::High,
            "medium" => ThreatLevel::Medium,
            "low" => ThreatLevel::Low,
            _ => ThreatLevel::Unknown,
        }
    }

    /// Convert ThreatLevel to Wireshark color code
    /// Returns (r, g, b) tuple
    #[cfg(test)]
    pub fn wireshark_color(&self) -> (u8, u8, u8) {
        match self {
            ThreatLevel::Critical => (0xFF, 0x00, 0x00), // Red
            ThreatLevel::High => (0xFF, 0x99, 0x00),     // Orange
            ThreatLevel::Medium => (0xFF, 0xFF, 0x00),   // Yellow
            ThreatLevel::Low => (0xFF, 0xFF, 0xCC),      // Light yellow
            ThreatLevel::Unknown => (0xFF, 0xFF, 0xFF),  // White
        }
    }

    /// Get numeric value for Wireshark field encoding
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Traffic Light Protocol (TLP) marking
/// Standard for information sharing with fixed values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tlp {
    Red = 1,
    AmberStrict = 2,
    Amber = 3,
    Green = 4,
    Clear = 5,
}

impl Tlp {
    /// Parse TLP from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "RED" => Some(Tlp::Red),
            "AMBER+STRICT" => Some(Tlp::AmberStrict),
            "AMBER" => Some(Tlp::Amber),
            "GREEN" => Some(Tlp::Green),
            "CLEAR" | "WHITE" => Some(Tlp::Clear), // WHITE is old name for CLEAR
            _ => None,
        }
    }

    /// Get numeric value for Wireshark field encoding
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Threat data extracted from matchy lookup
#[derive(Debug, Clone)]
pub struct ThreatData {
    pub level: ThreatLevel,
    pub category: String,
    pub source: String,
    /// Confidence score (0-100), STIX 2.1 compatible
    pub confidence: Option<u8>,
    /// Traffic Light Protocol marking for information sharing
    pub tlp: Option<Tlp>,
    /// When the indicator was last observed active (ISO 8601)
    pub last_seen: Option<String>,
    #[allow(dead_code)] // Stored for future detailed threat view
    pub metadata: serde_json::Value,
}

impl ThreatData {
    /// Parse threat data from matchy JSON result
    pub fn from_json(data: &serde_json::Value) -> Option<Self> {
        let level = data
            .get("threat_level")
            .and_then(|v| v.as_str())
            .map(ThreatLevel::from_str)
            .unwrap_or(ThreatLevel::Unknown);

        let category = data
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let source = data
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // ThreatDB optional fields
        let confidence = data
            .get("confidence")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v.min(100)).ok());

        let tlp = data
            .get("tlp")
            .and_then(|v| v.as_str())
            .and_then(Tlp::from_str);

        let last_seen = data
            .get("last_seen")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Some(ThreatData {
            level,
            category,
            source,
            confidence,
            tlp,
            last_seen,
            metadata: data.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_threat_level_colors() {
        assert_eq!(ThreatLevel::Critical.wireshark_color(), (0xFF, 0x00, 0x00));
        assert_eq!(ThreatLevel::High.wireshark_color(), (0xFF, 0x99, 0x00));
        assert_eq!(ThreatLevel::Medium.wireshark_color(), (0xFF, 0xFF, 0x00));
    }

    #[test]
    fn test_threat_level_from_string() {
        assert_eq!(ThreatLevel::from_str("CRITICAL"), ThreatLevel::Critical);
        assert_eq!(ThreatLevel::from_str("high"), ThreatLevel::High);
        assert_eq!(ThreatLevel::from_str("invalid"), ThreatLevel::Unknown);
    }

    #[test]
    fn test_threat_data_from_json() {
        let json = json!({
            "threat_level": "critical",
            "category": "malware",
            "source": "abuse.ch"
        });

        let threat = ThreatData::from_json(&json).unwrap();
        assert_eq!(threat.level, ThreatLevel::Critical);
        assert_eq!(threat.category, "malware");
        assert_eq!(threat.source, "abuse.ch");
    }

    #[test]
    fn test_threatdb_optional_fields() {
        let json = json!({
            "threat_level": "high",
            "category": "c2",
            "source": "emergingthreats",
            "confidence": 85,
            "tlp": "amber",
            "last_seen": "2024-12-01T12:00:00Z"
        });

        let threat = ThreatData::from_json(&json).unwrap();
        assert_eq!(threat.confidence, Some(85));
        assert_eq!(threat.tlp, Some(Tlp::Amber));
        assert_eq!(threat.last_seen, Some("2024-12-01T12:00:00Z".to_string()));
    }
}
