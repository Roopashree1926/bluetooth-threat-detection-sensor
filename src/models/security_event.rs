use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,

    pub sensor_id: String,

    pub timestamp: String,

    pub device_mac: Option<String>,

    pub device_name: Option<String>,

    pub bus_type: String,

    pub source: String,

    pub direction: String,

    pub event_type: String,

    pub severity: String,

    pub confidence: u8,

    pub signature: String,

    pub soc_incident: String,

    pub soc_status: String,

    pub evidence_hash: String,

    pub action_hint: String,

    pub details: String,
}