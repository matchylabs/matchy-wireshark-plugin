//! Threat matching and packet colorization
//!
//! Handles IP/domain lookups and visual threat indicators.

/// Threat level representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatLevel {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
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

    /// Get display string
    pub fn display_str(&self) -> &'static str {
        match self {
            ThreatLevel::Critical => "Critical",
            ThreatLevel::High => "High",
            ThreatLevel::Medium => "Medium",
            ThreatLevel::Low => "Low",
            ThreatLevel::Unknown => "Unknown",
        }
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
    pub tlp: Option<String>,
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
            .map(|s| s.to_string());

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
        assert_eq!(threat.tlp, Some("amber".to_string()));
        assert_eq!(threat.last_seen, Some("2024-12-01T12:00:00Z".to_string()));
    }
}
