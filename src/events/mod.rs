use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::models::incident::SecurityIncident;
use crate::models::security_event::SecurityEvent;

pub struct EventGenerator;

impl EventGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate(
        &self,
        incident: &SecurityIncident,
    ) -> SecurityEvent {

        /*
         * Generate SHA256 evidence hash
         */

        let mut hasher = Sha256::new();

        hasher.update(
            incident.details.as_bytes()
        );

        let evidence_hash =
            format!("{:x}", hasher.finalize());

        /*
         * Convert incident status into text
         */

        let soc_status =
            format!("{:?}", incident.status);

        /*
         * Map threat → confidence
         */

        let confidence = match incident.threat_name.as_str() {

            "Authentication Brute Force" => 98,

            "Suspicious Connection Cycling" => 94,

            "Advertising Flood" => 91,

            "Reconnection Flood" => 95,

            "Encryption Downgrade" => 99,

            _ => 80,
        };

        /*
         * Map threat → signature
         */

        let signature = match incident.threat_name.as_str() {

            "Authentication Brute Force" =>
                "authentication_bruteforce",

            "Suspicious Connection Cycling" =>
                "connection_cycle_detection",

            "Advertising Flood" =>
                "advertising_flood",

            "Reconnection Flood" =>
                "reconnection_flood",

            "Encryption Downgrade" =>
                "encryption_downgrade",

            _ =>
                "generic_detection",
        };

        /*
         * Map threat → suggested response
         */

        let action_hint = match incident.threat_name.as_str() {

            "Authentication Brute Force" =>
                "contain_device",

            "Encryption Downgrade" =>
                "contain_device",

            "Reconnection Flood" =>
                "disconnect_device",

            "Advertising Flood" =>
                "monitor",

            _ =>
                "log_and_alert",
        };

        SecurityEvent {

            event_id:
                format!(
                    "BT_EVT_{}",
                    incident.id.replace("INC-", "")
                ),

            sensor_id:
                "bluetooth-sensor-01".to_string(),

            timestamp:
                Utc::now().to_rfc3339(),

            device_mac:
                incident.device_mac.clone(),

            device_name:
                None,

            bus_type:
                "Bluetooth".to_string(),

            source:
                "hci0".to_string(),

            direction:
                "rx".to_string(),

            event_type:
                incident.threat_name.clone(),

            severity:
                incident.severity.clone(),

            confidence,

            signature:
                signature.to_string(),

            soc_incident:
                incident.id.clone(),

            soc_status,

            evidence_hash:
                evidence_hash,

            action_hint:
                action_hint.to_string(),

            details:
                incident.details.clone(),
        }
    }
}