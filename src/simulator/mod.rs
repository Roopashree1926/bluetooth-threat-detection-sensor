use std::time::Duration;

use chrono::Utc;

use crate::models::{BluetoothEvent, EventType};

pub struct AttackSimulator;

impl AttackSimulator {
    /*
     * Create one synthetic Bluetooth security event.
     *
     * IMPORTANT:
     * The simulator only creates events.
     * It does NOT trigger alerts directly.
     *
     * PatternDetector decides whether a rule matches.
     */
    pub fn create_event(
        event_type: EventType,
        mac: &str,
        description: &str,
    ) -> BluetoothEvent {
        BluetoothEvent {
            timestamp: Utc::now(),

            event_type,

            mac: Some(mac.to_string()),

            device_name: Some(
                "Authorized Test Device".to_string()
            ),

            rssi: None,

            hci_interface: Some("hci0".to_string()),

            connection_handle: None,

            role: None,

            encryption_enabled: None,

            key_size: None,

            l2cap_cid: None,

            service_uuid: None,

            hci_event_code: None,

            raw_line: description.to_string(),
        }
    }

    /*
     * Return:
     *
     * EventType
     * Number of events
     * Delay between events
     * Test MAC
     * Description
     */
    pub fn simulation_config(
        choice: u32,
    ) -> Option<(EventType, usize, Duration, &'static str, &'static str)> {
        match choice {
            1 => Some((
                EventType::AdvertisingReport,
                20,
                Duration::from_millis(300),
                "DE:AD:BE:EF:00:01",
                "SIMULATED Advertising Report",
            )),

            2 => Some((
                EventType::ConnectionFailed,
                3,
                Duration::from_secs(1),
                "DE:AD:BE:EF:00:02",
                "SIMULATED Connection Failed",
            )),

            3 => Some((
                EventType::AuthenticationFailed,
                3,
                Duration::from_secs(1),
                "DE:AD:BE:EF:00:03",
                "SIMULATED Authentication Failed",
            )),

            4 => Some((
                EventType::PairingRequest,
                5,
                Duration::from_secs(1),
                "DE:AD:BE:EF:00:04",
                "SIMULATED Pairing Request",
            )),

            5 => Some((
                EventType::DisconnectionComplete,
                5,
                Duration::from_secs(1),
                "DE:AD:BE:EF:00:05",
                "SIMULATED Disconnection",
            )),

            6 => Some((
                EventType::ConnectionReestablished,
                5,
                Duration::from_secs(1),
                "DE:AD:BE:EF:00:06",
                "SIMULATED Connection Reestablished",
            )),

            7 => Some((
                EventType::EncryptionDowngrade,
                1,
                Duration::from_millis(100),
                "DE:AD:BE:EF:00:07",
                "SIMULATED Encryption Downgrade",
            )),

            8 => Some((
                EventType::HCIError,
                5,
                Duration::from_secs(1),
                "DE:AD:BE:EF:00:08",
                "SIMULATED HCI Error",
            )),

            _ => None,
        }
    }

    pub fn rule_name(choice: u32) -> &'static str {
        match choice {
            1 => "Advertising Flood",
            2 => "Repeated Connection Failure",
            3 => "Authentication Brute Force",
            4 => "Pairing Request Flood",
            5 => "Repeated Disconnection Activity",
            6 => "Reconnection Flood",
            7 => "Encryption Downgrade",
            8 => "HCI Error Spike",
            _ => "Unknown Simulation",
        }
    }
}