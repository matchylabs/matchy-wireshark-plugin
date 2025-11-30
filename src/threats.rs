//! Threat matching and packet colorization
//!
//! Handles IP/domain lookups and visual threat indicators.

use serde_json::{json, Value};

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

        Some(ThreatData {
            level,
            category,
            source,
            metadata: data.clone(),
        })
    }

    /// Convert to JSON for Wireshark display
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "threat_detected": true,
            "level": self.level.display_str(),
            "category": self.category,
            "source": self.source,
            "metadata": self.metadata
        })
    }
}

/// Lookup indicator in threat database
pub fn lookup_threat(_indicator: &str) -> Option<ThreatData> {
    // TODO: Call matchy database lookup
    // Examples:
    // - IP: "1.2.3.4"
    // - CIDR: "1.2.3.0/24"
    // - Domain: "evil.com" or "*.evil.com"
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
