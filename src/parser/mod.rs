pub mod packet_builder;

use chrono::Utc;
use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::models::{BluetoothEvent, EventType};

static BUILDER: Lazy<Mutex<packet_builder::PacketBuilder>> =
    Lazy::new(|| Mutex::new(packet_builder::PacketBuilder::new()));

pub fn parse_line(line: &str) -> Option<BluetoothEvent> {

    let mut builder = BUILDER.lock().unwrap();

    let packet = builder.push_line(line)?;

    let event_type =
        if packet.raw_data.contains("LE Extended Advertising Report")
            || packet.raw_data.contains("LE Advertising Report")
        {
            EventType::AdvertisingReport
        }
        else if packet.raw_data.contains("Connection Complete") {
            EventType::ConnectionComplete
        }
        else if packet.raw_data.contains("Disconnection Complete") {
            EventType::DisconnectionComplete
        }
        else if packet.raw_data.contains("Authentication Complete") {
            EventType::AuthenticationComplete
        }
        else if packet.raw_data.contains("Authentication Failed") {
            EventType::AuthenticationFailed
        }
        else if packet.raw_data.contains("Encryption Change") {
            EventType::EncryptionChange
        }
        else if packet.raw_data.contains("Simple Pairing Complete") {
            EventType::PairingComplete
        }
        else if packet.raw_data.contains("Pairing Request") {
            EventType::PairingRequest
        }
        else if packet.raw_data.contains("IO Capability Request") {
            EventType::IOCapabilityRequest
        }
        else if packet.raw_data.contains("User Confirmation Request") {
            EventType::UserConfirmationRequest
        }
        else if packet.raw_data.contains("User Passkey Request") {
            EventType::PasskeyRequest
        }
        else if packet.raw_data.contains("Device Found") {
            EventType::DeviceFound
        }
        else if packet.raw_data.contains("Device Lost") {
            EventType::DeviceLost
        }
        else if packet.raw_data.contains("Service Discovery") {
            EventType::ServiceDiscovery
        }
        else if packet.rssi.is_some() {
            EventType::RSSIUpdate
        }
        else {
            EventType::Unknown
        };

    Some(BluetoothEvent {
        timestamp: Utc::now(),
        event_type,
        mac: Some(packet.mac),
        device_name: packet.name,
        rssi: packet.rssi,
        hci_interface: Some("hci0".to_string()),
        raw_line: packet.raw_data,
    })
}