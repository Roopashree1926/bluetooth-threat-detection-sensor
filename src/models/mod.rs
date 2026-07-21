pub mod threat;
pub mod alert;
pub mod incident;
pub mod security_event;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    AdvertisingReport,

    // Connection events
    ConnectionComplete,
    ConnectionFailed,
    DisconnectionComplete,
    ConnectionReestablished,

    // Authentication events
    AuthenticationComplete,
    AuthenticationFailed,

    // Pairing events
    PairingRequest,
    PairingComplete,

    // Encryption events
    EncryptionChange,
    EncryptionKeySize,
    EncryptionDowngrade,

    // Role telemetry
    RoleChange,

    // Signal telemetry
    RSSIUpdate,

    // Device discovery telemetry
    DeviceFound,
    DeviceLost,

    // Service discovery telemetry
    ServiceDiscovery,

    // L2CAP telemetry
    L2CAPConnectionRequest,
    L2CAPChannelOpen,
    L2CAPChannelClose,

    // Pairing security telemetry
    IOCapabilityRequest,
    UserConfirmationRequest,
    PasskeyRequest,

    // Controller telemetry
    HCIError,
    VendorSpecificEvent,

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

    pub connection_handle: Option<u16>,

    pub role: Option<String>,

    pub encryption_enabled: Option<bool>,

    pub key_size: Option<u8>,

    pub l2cap_cid: Option<u16>,

    pub service_uuid: Option<String>,

    pub hci_event_code: Option<String>,

    pub raw_line: String,
}

#[derive(Debug, Clone)]
pub struct BluetoothPacket {
    pub mac: String,

    pub name: Option<String>,

    pub rssi: Option<i16>,

    pub connection_handle: Option<u16>,

    pub role: Option<String>,

    pub encryption_enabled: Option<bool>,

    pub key_size: Option<u8>,

    pub l2cap_cid: Option<u16>,

    pub service_uuid: Option<String>,

    pub hci_event_code: Option<String>,

    pub raw_data: String,
}