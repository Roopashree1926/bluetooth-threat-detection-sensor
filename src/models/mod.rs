pub mod threat;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    AdvertisingReport,
    ConnectionComplete,
    DisconnectionComplete,
    AuthenticationComplete,
    AuthenticationFailed,
    PairingRequest,
    PairingComplete,
    EncryptionChange,
    RSSIUpdate,
    DeviceFound,
    DeviceLost,
    ServiceDiscovery,
    IOCapabilityRequest,
    UserConfirmationRequest,
    PasskeyRequest,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BluetoothEvent {

    pub timestamp: DateTime<Utc>,

    pub event_type: EventType,

    pub mac: Option<String>,

    pub device_name: Option<String>,

    pub rssi: Option<i16>,

    pub hci_interface: Option<String>,

    pub raw_line: String,

}

#[derive(Debug, Clone)]
pub struct BluetoothPacket {

    pub mac: String,

    pub name: Option<String>,

    pub rssi: Option<i16>,

    pub raw_data: String,

}