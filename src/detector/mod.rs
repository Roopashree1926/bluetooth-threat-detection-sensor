use std::collections::{
    HashMap,
    HashSet,
    VecDeque,
};

use chrono::Utc;

use crate::json_logger;
use crate::logger;

use crate::models::alert::SecurityAlert;

use crate::models::{
    BluetoothEvent,
    EventType,
};

use crate::reports;

use crate::signatures::{
    load_signatures,
    DetectionMode,
    Signature,
};


pub struct PatternDetector {

    signatures: Vec<Signature>,

    /*
     * Active alert key:
     *
     * RULE|MAC
     *
     * Example:
     *
     * Authentication Brute Force|AA:BB:CC:DD:EE:FF
     *
     * Prevents the same continuing condition from
     * generating hundreds of duplicate SOC incidents.
     */

    active_alerts:
        HashMap<String, bool>,
}


impl PatternDetector {

    pub fn new() -> Self {

        Self {

            signatures:
                load_signatures(),

            active_alerts:
                HashMap::new(),
        }
    }


    /*
     * ========================================================
     * MAIN DETECTION ENGINE
     * ========================================================
     */

    pub fn process(
        &mut self,
        events: &VecDeque<BluetoothEvent>,
    ) -> Vec<SecurityAlert> {

        let mut detected_alerts =
            Vec::new();

        let now =
            Utc::now();


        /*
         * Process each security rule.
         */

        for signature in &self.signatures {

            match signature.detection_mode {

                /*
                 * =============================================
                 * STANDARD EVENT COUNT RULE
                 * =============================================
                 */

                DetectionMode::EventCount => {

                    let counts =
                        Self::count_events_per_device(
                            events,
                            signature,
                            now,
                        );


                    for (mac, count) in &counts {

                        if *count >= signature.threshold {

                            Self::trigger_if_new(

                                &mut self.active_alerts,

                                &mut detected_alerts,

                                signature,

                                mac,

                                *count,

                                format!(

                                    "{} Device {} generated {} matching events within {} seconds. Threshold: {}.",

                                    signature.description,

                                    mac,

                                    count,

                                    signature.window_seconds,

                                    signature.threshold,
                                ),
                            );
                        }
                    }


                    /*
                     * Reset alert after condition clears.
                     */

                    Self::reset_cleared_alerts(

                        &mut self.active_alerts,

                        signature,

                        &counts,
                    );
                }


                /*
                 * =============================================
                 * CONNECTION-CYCLE DETECTION
                 * =============================================
                 *
                 * Detect:
                 *
                 * CONNECT
                 * DISCONNECT
                 * CONNECT
                 * DISCONNECT
                 *
                 * from the SAME MAC.
                 */

                DetectionMode::ConnectionCycle => {

                    let cycles =
                        Self::count_connection_cycles(
                            events,
                            signature.window_seconds,
                            now,
                        );


                    for (mac, count) in &cycles {

                        if *count >= signature.threshold {

                            Self::trigger_if_new(

                                &mut self.active_alerts,

                                &mut detected_alerts,

                                signature,

                                mac,

                                *count,

                                format!(

                                    "{} Device {} completed {} rapid connection/disconnection cycles within {} seconds. Threshold: {} cycles.",

                                    signature.description,

                                    mac,

                                    count,

                                    signature.window_seconds,

                                    signature.threshold,
                                ),
                            );
                        }
                    }


                    Self::reset_cleared_alerts(

                        &mut self.active_alerts,

                        signature,

                        &cycles,
                    );
                }


                /*
                 * =============================================
                 * IMMEDIATE SECURITY EVENT
                 * =============================================
                 */

                DetectionMode::Immediate => {

                    let counts =
                        Self::count_events_per_device(
                            events,
                            signature,
                            now,
                        );


                    for (mac, count) in &counts {

                        if *count >= 1 {

                            Self::trigger_if_new(

                                &mut self.active_alerts,

                                &mut detected_alerts,

                                signature,

                                mac,

                                *count,

                                format!(

                                    "{} Device: {}.",

                                    signature.description,

                                    mac,
                                ),
                            );
                        }
                    }


                    Self::reset_cleared_alerts(

                        &mut self.active_alerts,

                        signature,

                        &counts,
                    );
                }
            }
        }


        detected_alerts
    }


    /*
     * ========================================================
     * COUNT EVENTS PER DEVICE
     * ========================================================
     */

    fn count_events_per_device(

        events:
            &VecDeque<BluetoothEvent>,

        signature:
            &Signature,

        now:
            chrono::DateTime<Utc>,

    ) -> HashMap<String, usize> {

        let mut counts =
            HashMap::new();


        for event in events {

            /*
             * Correct event type?
             */

            if event.event_type
                != signature.event_type
            {

                continue;
            }


            /*
             * Inside rule time window?
             */

            let age =
                now.signed_duration_since(
                    event.timestamp
                );


            if age.num_seconds() < 0

                || age.num_seconds()
                    > signature.window_seconds
            {

                continue;
            }


            /*
             * Must have valid MAC.
             */

            let Some(mac) =
                Self::valid_mac(event)
            else {

                continue;
            };


            *counts
                .entry(mac)
                .or_insert(0) += 1;
        }


        counts
    }


    /*
     * ========================================================
     * COUNT CONNECTION/DISCONNECTION CYCLES
     * ========================================================
     *
     * A cycle requires:
     *
     * ConnectionComplete
     *        ↓
     * DisconnectionComplete
     *
     * for the SAME MAC.
     *
     * Duplicate connection events do not create extra cycles.
     */

    fn count_connection_cycles(

        events:
            &VecDeque<BluetoothEvent>,

        window_seconds:
            i64,

        now:
            chrono::DateTime<Utc>,

    ) -> HashMap<String, usize> {

        /*
         * MACs currently considered connected while
         * walking through recent event history.
         */

        let mut connected:
            HashSet<String> =
            HashSet::new();


        /*
         * Completed cycles per MAC.
         */

        let mut cycles:
            HashMap<String, usize> =
            HashMap::new();


        for event in events {

            /*
             * Ignore events outside time window.
             */

            let age =
                now.signed_duration_since(
                    event.timestamp
                );


            if age.num_seconds() < 0

                || age.num_seconds()
                    > window_seconds
            {

                continue;
            }


            let Some(mac) =
                Self::valid_mac(event)
            else {

                continue;
            };


            match event.event_type {

                /*
                 * Device enters connected state.
                 */

                EventType::ConnectionComplete => {

                    connected.insert(
                        mac
                    );
                }


                /*
                 * Count a cycle only if the same MAC
                 * was previously observed connected.
                 */

                EventType::DisconnectionComplete => {

                    if connected.remove(
                        &mac
                    ) {

                        *cycles
                            .entry(mac)
                            .or_insert(0) += 1;
                    }
                }


                _ => {}
            }
        }


        cycles
    }


    /*
     * ========================================================
     * VALIDATE MAC
     * ========================================================
     */

    fn valid_mac(
        event: &BluetoothEvent,
    ) -> Option<String> {

        match &event.mac {

            Some(mac)

                if !mac.trim().is_empty()

                && mac != "Unknown" =>

            {

                Some(
                    mac.to_uppercase()
                )
            }


            _ => None,
        }
    }


    /*
     * ========================================================
     * TRIGGER SECURITY ALERT
     * ========================================================
     */

    fn trigger_if_new(

        active_alerts:
            &mut HashMap<String, bool>,

        detected_alerts:
            &mut Vec<SecurityAlert>,

        signature:
            &Signature,

        mac:
            &str,

        count:
            usize,

        details:
            String,

    ) {

        let alert_key =
            format!(
                "{}|{}",
                signature.name,
                mac
            );


        let is_active =
            active_alerts
                .get(&alert_key)
                .copied()
                .unwrap_or(false);


        /*
         * Existing active alert?
         *
         * Do not create another SOC incident.
         */

        if is_active {

            return;
        }


        /*
         * ====================================================
         * SECURITY RULE MATCHED
         * ====================================================
         */

        println!();

        println!(
            "############################################################"
        );

        println!(
            "                 SECURITY ALERT TRIGGERED"
        );

        println!(
            "############################################################"
        );

        println!(
            "Rule Name   : {}",
            signature.name
        );

        println!(
            "Severity    : {}",
            signature.severity
        );

        println!(
            "Device MAC  : {}",
            mac
        );

        println!(
            "Event Count : {}",
            count
        );

        println!(
            "Threshold   : {}",
            signature.threshold
        );

        println!(
            "Time Window : {} seconds",
            signature.window_seconds
        );

        println!(
            "Description : {}",
            signature.description
        );

        println!(
            "Action      : SEND TO SOC FOR VALIDATION"
        );

        println!(
            "############################################################"
        );

        println!();


        /*
         * ====================================================
         * LOG SECURITY ALERT
         * ====================================================
         */

        logger::log_threat(

            signature.name,

            signature.severity,
        );


        json_logger::log_json(

            signature.name,

            signature.severity,

            &details,
        );


        reports::generate_report(

            signature.name,

            signature.severity,

            &details,
        );


        /*
         * Mark alert active.
         */

        active_alerts.insert(

            alert_key,

            true,
        );


        /*
         * Send alert back to main.rs.
         *
         * main.rs creates the SOC incident.
         */

        detected_alerts.push(

            SecurityAlert {

                name:
                    signature.name
                        .to_string(),

                severity:
                    signature.severity
                        .to_string(),

                mac:
                    Some(
                        mac.to_string()
                    ),

                details,
            }
        );
    }


    /*
     * ========================================================
     * RESET CLEARED ALERTS
     * ========================================================
     */

    fn reset_cleared_alerts(

        active_alerts:
            &mut HashMap<String, bool>,

        signature:
            &Signature,

        counts:
            &HashMap<String, usize>,

    ) {

        let prefix =
            format!(
                "{}|",
                signature.name
            );


        let keys:
            Vec<String> =

            active_alerts
                .keys()

                .filter(
                    |key| {
                        key.starts_with(
                            &prefix
                        )
                    }
                )

                .cloned()

                .collect();


        for key in keys {

            let Some(
                (_, mac)
            ) =
                key.split_once('|')

            else {

                continue;
            };


            let count =
                counts
                    .get(mac)
                    .copied()
                    .unwrap_or(0);


            /*
             * Once the old activity leaves the time window,
             * clear the alert.
             *
             * A genuinely new incident can then trigger later.
             */

            if count
                < signature.threshold
            {

                active_alerts.insert(

                    key,

                    false,
                );
            }
        }
    }
}