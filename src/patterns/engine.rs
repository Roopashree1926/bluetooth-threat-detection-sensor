use std::collections::VecDeque;

use crate::models::{BluetoothEvent, EventType};

pub struct PatternEngine;

impl PatternEngine {

    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, events: &VecDeque<BluetoothEvent>) {

        self.detect_advertising_flood(events);
        self.detect_pairing_attack(events);

    }

    fn detect_advertising_flood(&self, events: &VecDeque<BluetoothEvent>) {

        let advertising = events
            .iter()
            .filter(|e| e.event_type == EventType::AdvertisingReport)
            .count();

        if advertising >= 20 {

            println!();
            println!("==============================");
            println!("THREAT DETECTED");
            println!("Pattern : Advertising Flood");
            println!("Severity: Medium");
            println!("Events  : {}", advertising);
            println!("==============================");
            println!();

        }

    }

    fn detect_pairing_attack(&self, events: &VecDeque<BluetoothEvent>) {

        let pairing = events
            .iter()
            .filter(|e| e.event_type == EventType::PairingRequest)
            .count();

        let auth_failed = events
            .iter()
            .filter(|e| e.event_type == EventType::AuthenticationFailed)
            .count();

        if pairing >= 3 && auth_failed >= 3 {

            println!();
            println!("==============================");
            println!("THREAT DETECTED");
            println!("Pattern : Possible Pairing Attack");
            println!("Severity: High");
            println!("Pairings: {}", pairing);
            println!("Failures: {}", auth_failed);
            println!("==============================");
            println!();

        }

    }

}