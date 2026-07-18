use colored::*;
use chrono::Local;

use crate::models::{BluetoothEvent, EventType};

pub struct Dashboard {
    packets: usize,
    advertising: usize,
    devices: usize,
    auth_failures: usize,
    pairing: usize,
    connections: usize,
    disconnections: usize,
    rssi_updates: usize,

    threats: usize,
    latest: String,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            packets: 0,
            advertising: 0,
            devices: 0,
            auth_failures: 0,
            pairing: 0,
            connections: 0,
            disconnections: 0,
            rssi_updates: 0,

            threats: 0,
            latest: "None".to_string(),
        }
    }

    pub fn update(&mut self, event: &BluetoothEvent) {

        self.packets += 1;

        match event.event_type {

            EventType::AdvertisingReport => self.advertising += 1,

            EventType::DeviceFound => self.devices += 1,

            EventType::AuthenticationFailed => self.auth_failures += 1,

            EventType::PairingRequest => self.pairing += 1,

            EventType::ConnectionComplete => self.connections += 1,

            EventType::DisconnectionComplete => self.disconnections += 1,

            EventType::RSSIUpdate => self.rssi_updates += 1,

            _ => {}

        }
    }

    pub fn threat(&mut self, name: &str) {

        // Count only if this is a NEW threat
        if self.latest != name {

            self.latest = name.to_string();

            self.threats += 1;

        }

    }

    pub fn display(&self) {

        print!("\x1B[2J\x1B[1;1H");

        println!("{}", "============================================================".blue());

        println!("{}", "        BLUETOOTH THREAT DETECTION SENSOR".bold().green());

        println!("{}", "============================================================".blue());

        println!("{} {}", "System Status :".yellow(), "RUNNING".green().bold());

        println!(
            "{} {}",
            "Monitoring Time :".yellow(),
            Local::now().format("%H:%M:%S")
        );

        println!("{}", "------------------------------------------------------------".blue());

        println!("Packets Captured        : {}", self.packets);

        println!("Advertising Reports     : {}", self.advertising);

        println!("Connections             : {}", self.connections);

        println!("Disconnections          : {}", self.disconnections);

        println!("Devices Found           : {}", self.devices);

        println!("RSSI Updates            : {}", self.rssi_updates);

        println!("Authentication Failures : {}", self.auth_failures);

        println!("Pairing Requests        : {}", self.pairing);

        println!("{}", "------------------------------------------------------------".blue());

        println!("{} {}", "Threats Detected :".red().bold(), self.threats);

        println!("{} {}", "Latest Threat :".red().bold(), self.latest.red().bold());

        println!("{}", "============================================================".blue());

        println!("{}", "Monitoring Bluetooth Traffic...".green());

        println!("{}", "============================================================".blue());
    }
}