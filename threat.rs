use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {

    pub name: String,

    pub severity: String,

    pub description: String,

    pub timestamp: String,

    pub mac: Option<String>,

    pub device_name: Option<String>,

    pub rssi: Option<i16>,

    pub raw_packet: String,

}