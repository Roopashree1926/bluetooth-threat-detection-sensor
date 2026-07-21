use crate::models::EventType;

#[derive(Debug, Clone, PartialEq)]
pub enum DetectionMode {
    /*
     * Count matching events from the same MAC
     * inside the configured time window.
     */
    EventCount,

    /*
     * Look for repeated connect -> disconnect cycles
     * from the same MAC.
     */
    ConnectionCycle,

    /*
     * One event is enough to generate an alert.
     */
    Immediate,
}


#[derive(Debug, Clone)]
pub struct Signature {
    pub name: &'static str,

    pub event_type: EventType,

    pub threshold: usize,

    pub window_seconds: i64,

    pub severity: &'static str,

    pub description: &'static str,

    pub detection_mode: DetectionMode,
}


pub fn load_signatures() -> Vec<Signature> {

    vec![

        /*
         * ====================================================
         * 1. ADVERTISING FLOOD
         * ====================================================
         *
         * Must come from the SAME MAC.
         */

        Signature {

            name:
                "Advertising Flood",

            event_type:
                EventType::AdvertisingReport,

            threshold:
                20,

            window_seconds:
                10,

            severity:
                "Medium",

            description:
                "Abnormally high Bluetooth advertising activity detected from one device.",

            detection_mode:
                DetectionMode::EventCount,
        },


        /*
         * ====================================================
         * 2. REPEATED CONNECTION FAILURE
         * ====================================================
         */

        Signature {

            name:
                "Repeated Connection Failure",

            event_type:
                EventType::ConnectionFailed,

            threshold:
                3,

            window_seconds:
                30,

            severity:
                "High",

            description:
                "Repeated failed Bluetooth connection attempts detected from one device.",

            detection_mode:
                DetectionMode::EventCount,
        },


        /*
         * ====================================================
         * 3. AUTHENTICATION BRUTE FORCE
         * ====================================================
         */

        Signature {

            name:
                "Authentication Brute Force",

            event_type:
                EventType::AuthenticationFailed,

            threshold:
                3,

            window_seconds:
                30,

            severity:
                "High",

            description:
                "Repeated Bluetooth authentication failures detected from one device.",

            detection_mode:
                DetectionMode::EventCount,
        },


        /*
         * ====================================================
         * 4. PAIRING REQUEST FLOOD
         * ====================================================
         */

        Signature {

            name:
                "Pairing Request Flood",

            event_type:
                EventType::PairingRequest,

            threshold:
                5,

            window_seconds:
                30,

            severity:
                "Medium",

            description:
                "Abnormally frequent Bluetooth pairing requests detected from one device.",

            detection_mode:
                DetectionMode::EventCount,
        },


        /*
         * ====================================================
         * 5. SUSPICIOUS CONNECTION CYCLING
         * ====================================================
         *
         * IMPORTANT:
         *
         * We no longer say:
         *
         *     5 disconnections = attack
         *
         * Instead we require repeated:
         *
         *     CONNECT
         *       ↓
         *     DISCONNECT
         *       ↓
         *     CONNECT
         *       ↓
         *     DISCONNECT
         *
         * from the SAME MAC inside the time window.
         */

        Signature {

            name:
                "Suspicious Connection Cycling",

            event_type:
                EventType::DisconnectionComplete,

            /*
             * 5 completed connection/disconnection cycles.
             */

            threshold:
                5,

            /*
             * 60 seconds is less likely to classify
             * occasional user reconnects as suspicious.
             */

            window_seconds:
                60,

            severity:
                "Medium",

            description:
                "Rapid repeated Bluetooth connection and disconnection cycles detected from the same device.",

            detection_mode:
                DetectionMode::ConnectionCycle,
        },


        /*
         * ====================================================
         * 6. RECONNECTION FLOOD
         * ====================================================
         */

        Signature {

            name:
                "Reconnection Flood",

            event_type:
                EventType::ConnectionReestablished,

            threshold:
                5,

            window_seconds:
                30,

            severity:
                "Medium",

            description:
                "Abnormally frequent Bluetooth reconnection activity detected from one device.",

            detection_mode:
                DetectionMode::EventCount,
        },


        /*
         * ====================================================
         * 7. ENCRYPTION DOWNGRADE
         * ====================================================
         */

        Signature {

            name:
                "Encryption Downgrade",

            event_type:
                EventType::EncryptionDowngrade,

            threshold:
                1,

            window_seconds:
                60,

            severity:
                "High",

            description:
                "Potential Bluetooth encryption downgrade detected.",

            detection_mode:
                DetectionMode::Immediate,
        },


        /*
         * ====================================================
         * 8. HCI ERROR SPIKE
         * ====================================================
         */

        Signature {

            name:
                "HCI Error Spike",

            event_type:
                EventType::HCIError,

            threshold:
                5,

            window_seconds:
                30,

            severity:
                "Medium",

            description:
                "Repeated Bluetooth controller errors detected from the same device.",

            detection_mode:
                DetectionMode::EventCount,
        },
    ]
}