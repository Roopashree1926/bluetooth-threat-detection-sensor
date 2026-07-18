use std::collections::VecDeque;

use crate::json_logger;
use crate::logger;
use crate::models::{BluetoothEvent, EventType};
use crate::reports;

pub struct PatternDetector;

impl PatternDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn process(&self, events: &VecDeque<BluetoothEvent>) {
        self.detect_advertising_flood(events);
        self.detect_authentication_failures(events);
        self.detect_pairing_flood(events);
        self.detect_device_discovery_flood(events);
        self.detect_rapid_connect_disconnect(events);
        self.detect_suspicious_auth_sequence(events);
    }

    fn detect_advertising_flood(&self, events: &VecDeque<BluetoothEvent>) {
        let advertising = events
            .iter()
            .filter(|e| e.event_type == EventType::AdvertisingReport)
            .count();

        if advertising >= 10 {
            println!();
            println!("################################");
            println!("SIGNATURE MATCHED");
            println!("Name      : Advertising Flood");
            println!("Severity  : Medium");
            println!("Advertising Packets : {}", advertising);
            println!("################################");
            println!();

            logger::log_threat("Advertising Flood", "Medium");

            reports::generate_report(
                "Advertising Flood",
                "Medium",
                &format!("Advertising packets detected: {}", advertising),
            );

            json_logger::log_json(
                "Advertising Flood",
                "Medium",
                &format!("Advertising packets detected: {}", advertising),
            );
        }
    }

    fn detect_authentication_failures(&self, events: &VecDeque<BluetoothEvent>) {
        let failed = events
            .iter()
            .filter(|e| e.event_type == EventType::AuthenticationFailed)
            .count();

        if failed >= 3 {
            println!();
            println!("################################");
            println!("SIGNATURE MATCHED");
            println!("Name      : Authentication Failure");
            println!("Severity  : High");
            println!("Failures  : {}", failed);
            println!("################################");
            println!();

            logger::log_threat("Authentication Failure", "High");

            reports::generate_report(
                "Authentication Failure",
                "High",
                &format!("Authentication failures detected: {}", failed),
            );

            json_logger::log_json(
                "Authentication Failure",
                "High",
                &format!("Authentication failures detected: {}", failed),
            );
        }
    }

    fn detect_pairing_flood(&self, events: &VecDeque<BluetoothEvent>) {
        let pairing = events
            .iter()
            .filter(|e| e.event_type == EventType::PairingRequest)
            .count();

        if pairing >= 5 {
            println!();
            println!("################################");
            println!("SIGNATURE MATCHED");
            println!("Name      : Pairing Request Flood");
            println!("Severity  : High");
            println!("Pairing Requests : {}", pairing);
            println!("################################");
            println!();

            logger::log_threat("Pairing Request Flood", "High");

            reports::generate_report(
                "Pairing Request Flood",
                "High",
                &format!("Repeated pairing requests: {}", pairing),
            );

            json_logger::log_json(
                "Pairing Request Flood",
                "High",
                &format!("Repeated pairing requests: {}", pairing),
            );
        }
    }

    fn detect_device_discovery_flood(&self, events: &VecDeque<BluetoothEvent>) {
        let devices = events
            .iter()
            .filter(|e| e.event_type == EventType::DeviceFound)
            .count();

        if devices >= 20 {
            println!();
            println!("################################");
            println!("SIGNATURE MATCHED");
            println!("Name      : Device Discovery Flood");
            println!("Severity  : Medium");
            println!("Devices Found : {}", devices);
            println!("################################");
            println!();

            logger::log_threat("Device Discovery Flood", "Medium");

            reports::generate_report(
                "Device Discovery Flood",
                "Medium",
                &format!("Devices discovered: {}", devices),
            );

            json_logger::log_json(
                "Device Discovery Flood",
                "Medium",
                &format!("Devices discovered: {}", devices),
            );
        }
    }

    fn detect_rapid_connect_disconnect(&self, events: &VecDeque<BluetoothEvent>) {
        let connect = events
            .iter()
            .filter(|e| e.event_type == EventType::ConnectionComplete)
            .count();

        let disconnect = events
            .iter()
            .filter(|e| e.event_type == EventType::DisconnectionComplete)
            .count();

        if connect >= 5 && disconnect >= 5 {
            println!();
            println!("################################");
            println!("SIGNATURE MATCHED");
            println!("Name      : Rapid Connect/Disconnect");
            println!("Severity  : High");
            println!("################################");
            println!();

            logger::log_threat("Rapid Connect Disconnect", "High");

            reports::generate_report(
                "Rapid Connect Disconnect",
                "High",
                "Repeated connect/disconnect events detected",
            );

            json_logger::log_json(
                "Rapid Connect Disconnect",
                "High",
                "Repeated connect/disconnect events detected",
            );
        }
    }

    fn detect_suspicious_auth_sequence(&self, events: &VecDeque<BluetoothEvent>) {
        let auth = events
            .iter()
            .filter(|e| e.event_type == EventType::AuthenticationComplete)
            .count();

        let failed = events
            .iter()
            .filter(|e| e.event_type == EventType::AuthenticationFailed)
            .count();

        if auth >= 1 && failed >= 3 {
            println!();
            println!("################################");
            println!("SIGNATURE MATCHED");
            println!("Name      : Suspicious Authentication Sequence");
            println!("Severity  : High");
            println!("################################");
            println!();

            logger::log_threat(
                "Suspicious Authentication Sequence",
                "High",
            );

            reports::generate_report(
                "Suspicious Authentication Sequence",
                "High",
                "Authentication success followed by repeated failures",
            );

            json_logger::log_json(
                "Suspicious Authentication Sequence",
                "High",
                "Authentication success followed by repeated failures",
            );
        }
    }
}