use regex::Regex;

use crate::models::BluetoothPacket;

pub struct PacketBuilder {
    current_mac: Option<String>,
    current_name: Option<String>,
    current_rssi: Option<i16>,
    current_data: Vec<String>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self {
            current_mac: None,
            current_name: None,
            current_rssi: None,
            current_data: Vec::new(),
        }
    }

    pub fn push_line(&mut self, line: &str) -> Option<BluetoothPacket> {

        // New packet begins
        if line.starts_with("> HCI Event:")
            || line.starts_with("@ MGMT Event:")
        {
            // Return previous packet first
            if !self.current_data.is_empty() && self.current_mac.is_some() {

                let packet = BluetoothPacket {
                    mac: self.current_mac.take().unwrap(),
                    name: self.current_name.take(),
                    rssi: self.current_rssi.take(),
                    raw_data: self.current_data.join("\n"),
                };

                self.current_data.clear();

                self.current_data.push(line.to_string());

                return Some(packet);
            }

            self.current_data.clear();
        }

        self.current_data.push(line.to_string());

        let mac_regex =
            Regex::new(r"([0-9A-F]{2}(:[0-9A-F]{2}){5})").unwrap();

        if let Some(cap) = mac_regex.captures(line) {
            self.current_mac = Some(cap[1].to_string());
        }

        if line.contains("RSSI:") {

            let rssi_regex =
                Regex::new(r"RSSI:\s*(-?\d+)").unwrap();

            if let Some(cap) = rssi_regex.captures(line) {
                self.current_rssi = cap[1].parse::<i16>().ok();
            }
        }

        if line.contains("Name (complete):") {

            self.current_name = Some(
                line.replace("Name (complete):", "")
                    .trim()
                    .to_string(),
            );
        }

        None
    }
}