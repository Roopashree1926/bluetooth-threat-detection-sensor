pub mod dataset;
pub mod trainer;
pub mod predictor;
pub mod model;
pub mod metrics;
pub mod labeler;


use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;

use chrono::{DateTime, Utc};

use crate::models::{
    BluetoothEvent,
    EventType,
};


/*
 * ============================================================
 * DEVICE FEATURE WINDOW
 * ============================================================
 *
 * Stores behavioral features for ONE Bluetooth device
 * during a fixed observation window.
 */

#[derive(Debug, Clone)]
struct DeviceWindow {

    start_time: DateTime<Utc>,

    connections: usize,

    disconnections: usize,

    connection_failures: usize,

    authentication_failures: usize,

    pairing_requests: usize,

    advertising_reports: usize,

    /*
     * Number of RSSIUpdate events detected.
     */
    rssi_updates: usize,

    /*
     * Number of RSSIUpdate events that actually
     * contained a valid numerical RSSI value.
     *
     * IMPORTANT:
     *
     * avg_rssi must use this counter, NOT rssi_updates.
     */
    valid_rssi_samples: usize,

    rssi_sum: i64,

    rssi_min: Option<i16>,

    rssi_max: Option<i16>,

    /*
     * Events that don't map to one of the
     * explicit behavioral feature categories.
     */
    other_events: usize,

    /*
     * Total parsed events associated with this device.
     */
    total_events: usize,
}


impl DeviceWindow {

    fn new() -> Self {

        Self {

            start_time:
                Utc::now(),

            connections:
                0,

            disconnections:
                0,

            connection_failures:
                0,

            authentication_failures:
                0,

            pairing_requests:
                0,

            advertising_reports:
                0,

            rssi_updates:
                0,

            valid_rssi_samples:
                0,

            rssi_sum:
                0,

            rssi_min:
                None,

            rssi_max:
                None,

            other_events:
                0,

            total_events:
                0,
        }
    }


    /*
     * ========================================================
     * AVERAGE RSSI
     * ========================================================
     *
     * Only valid numerical RSSI samples are included.
     */

    fn average_rssi(
        &self,
    ) -> f64 {

        if self.valid_rssi_samples == 0 {

            return 0.0;
        }


        self.rssi_sum as f64
            / self.valid_rssi_samples as f64
    }


    /*
     * ========================================================
     * RSSI RANGE
     * ========================================================
     *
     * Difference between strongest and weakest
     * RSSI observed in this window.
     */

    fn rssi_range(
        &self,
    ) -> i16 {

        match (
            self.rssi_min,
            self.rssi_max,
        ) {

            (
                Some(min),
                Some(max),
            ) => {

                max - min
            }


            _ => 0,
        }
    }
}


/*
 * ============================================================
 * ML DATA COLLECTOR
 * ============================================================
 */

pub struct MLDataCollector {

    /*
     * Output feature dataset.
     */

    file_path: String,


    /*
     * One active behavioral window
     * for each observed Bluetooth MAC.
     */

    windows:
        HashMap<String, DeviceWindow>,


    /*
     * Window duration.
     */

    window_seconds: i64,
}


impl MLDataCollector {

    /*
     * ========================================================
     * CREATE COLLECTOR
     * ========================================================
     */

    pub fn new(
        file_path: &str,
    ) -> Self {

        /*
         * Create CSV only when it does not already exist.
         */

        if !std::path::Path::new(
            file_path
        )
        .exists()
        {

            if let Ok(mut file) =

                OpenOptions::new()

                    .create(true)

                    .append(true)

                    .open(
                        file_path
                    )

            {

                /*
                 * ML FEATURE SCHEMA
                 */

                let _ = writeln!(
                    file,
                    "window_start,\
mac,\
connections,\
disconnections,\
connection_failures,\
authentication_failures,\
pairing_requests,\
advertising_reports,\
rssi_updates,\
valid_rssi_samples,\
avg_rssi,\
rssi_range,\
other_events,\
total_events,\
connection_disconnect_ratio,\
label"
                );
            }
        }


        Self {

            file_path:
                file_path.to_string(),

            windows:
                HashMap::new(),

            /*
             * 30-second behavioral window.
             */

            window_seconds:
                30,
        }
    }


    /*
     * ========================================================
     * VALIDATE MAC ADDRESS
     * ========================================================
     */

    fn valid_mac(
        mac: &str,
    ) -> bool {

        let normalized =
            mac.trim().to_uppercase();


        /*
         * Reject missing/placeholder addresses.
         */

        if normalized.is_empty()
            || normalized == "UNKNOWN"
            || normalized == "00:00:00:00:00:00"
        {

            return false;
        }


        /*
         * Basic Bluetooth MAC format validation.
         *
         * AA:BB:CC:DD:EE:FF
         */

        let parts:
            Vec<&str> =

            normalized
                .split(':')
                .collect();


        if parts.len() != 6 {

            return false;
        }


        for part in parts {

            if part.len() != 2 {

                return false;
            }


            if !part
                .chars()
                .all(
                    |character|
                        character.is_ascii_hexdigit()
                )
            {

                return false;
            }
        }


        true
    }


    /*
     * ========================================================
     * PROCESS BLUETOOTH EVENT
     * ========================================================
     */

    pub fn record_event(
        &mut self,
        event: &BluetoothEvent,
    ) {

        /*
         * ----------------------------------------------------
         * DEVICE MAC REQUIRED
         * ----------------------------------------------------
         */

        let Some(mac) =
            event.mac.as_ref()

        else {

            return;
        };


        /*
         * ----------------------------------------------------
         * FILTER INVALID MAC
         * ----------------------------------------------------
         */

        if !Self::valid_mac(
            mac
        )
        {

            return;
        }


        let normalized_mac =
            mac
                .trim()
                .to_uppercase();


        /*
         * ----------------------------------------------------
         * CHECK WINDOW EXPIRATION
         * ----------------------------------------------------
         *
         * If this device already has a window older
         * than 30 seconds, save it before adding the
         * new event.
         */

        let should_flush =

            self.windows
                .get(
                    &normalized_mac
                )

                .map(
                    |window| {

                        Utc::now()

                            .signed_duration_since(
                                window.start_time
                            )

                            .num_seconds()

                            >= self.window_seconds
                    }
                )

                .unwrap_or(
                    false
                );


        if should_flush {

            self.flush_device(
                &normalized_mac
            );
        }


        /*
         * ----------------------------------------------------
         * GET OR CREATE DEVICE WINDOW
         * ----------------------------------------------------
         */

        let window =

            self.windows
                .entry(
                    normalized_mac
                )

                .or_insert_with(
                    DeviceWindow::new
                );


        /*
         * Every accepted event belongs to this
         * device's total activity.
         */

        window.total_events += 1;


        /*
         * ====================================================
         * FEATURE EXTRACTION
         * ====================================================
         */

        match &event.event_type {

            /*
             * ------------------------------------------------
             * CONNECTION
             * ------------------------------------------------
             */

            EventType::ConnectionComplete => {

                window.connections += 1;
            }


            /*
             * ------------------------------------------------
             * DISCONNECTION
             * ------------------------------------------------
             */

            EventType::DisconnectionComplete => {

                window.disconnections += 1;
            }


            /*
             * ------------------------------------------------
             * CONNECTION FAILURE
             * ------------------------------------------------
             */

            EventType::ConnectionFailed => {

                window.connection_failures += 1;
            }


            /*
             * ------------------------------------------------
             * AUTHENTICATION FAILURE
             * ------------------------------------------------
             */

            EventType::AuthenticationFailed => {

                window.authentication_failures += 1;
            }


            /*
             * ------------------------------------------------
             * PAIRING REQUEST
             * ------------------------------------------------
             */

            EventType::PairingRequest => {

                window.pairing_requests += 1;
            }


            /*
             * ------------------------------------------------
             * ADVERTISING
             * ------------------------------------------------
             */

            EventType::AdvertisingReport => {

                window.advertising_reports += 1;
            }


            /*
             * ------------------------------------------------
             * RSSI
             * ------------------------------------------------
             */

            EventType::RSSIUpdate => {

                /*
                 * Count every RSSIUpdate event.
                 */

                window.rssi_updates += 1;


                /*
                 * Only count the sample for average/min/max
                 * when a real RSSI value exists.
                 */

                if let Some(rssi) =
                    event.rssi
                {

                    window.valid_rssi_samples += 1;


                    window.rssi_sum +=
                        rssi as i64;


                    /*
                     * Update minimum RSSI.
                     */

                    window.rssi_min =

                        Some(

                            match window.rssi_min {

                                Some(old_min) => {

                                    old_min.min(
                                        rssi
                                    )
                                }


                                None => {

                                    rssi
                                }
                            }
                        );


                    /*
                     * Update maximum RSSI.
                     */

                    window.rssi_max =

                        Some(

                            match window.rssi_max {

                                Some(old_max) => {

                                    old_max.max(
                                        rssi
                                    )
                                }


                                None => {

                                    rssi
                                }
                            }
                        );
                }
            }


            /*
             * ------------------------------------------------
             * OTHER EVENT
             * ------------------------------------------------
             *
             * This makes total_events explainable.
             */

            _ => {

                window.other_events += 1;
            }
        }
    }


    /*
     * ========================================================
     * SAVE ONE DEVICE WINDOW
     * ========================================================
     */

    fn flush_device(
        &mut self,
        mac: &str,
    ) {

        let Some(window) =

            self.windows.remove(
                mac
            )

        else {

            return;
        };


        /*
         * Ignore empty windows.
         */

        if window.total_events == 0 {

            return;
        }


        /*
         * ====================================================
         * CONNECTION / DISCONNECTION RATIO
         * ====================================================
         *
         * Keep this as an auxiliary feature.
         *
         * A value alone should NOT be interpreted as
         * malicious without considering other features.
         */

        let connection_disconnect_ratio =

            if window.disconnections == 0 {

                window.connections as f64

            } else {

                window.connections as f64
                    / window.disconnections as f64
            };


        /*
         * ====================================================
         * LABEL
         * ====================================================
         *
         * Do NOT automatically label this NORMAL or ATTACK.
         *
         * Proper labels will later come from:
         *
         * - controlled normal sessions
         * - controlled authorized test scenarios
         * - validated SOC decisions
         */

        let label =
            "UNLABELED";


        /*
         * ====================================================
         * WRITE FEATURE ROW
         * ====================================================
         */

        if let Ok(mut file) =

            OpenOptions::new()

                .create(true)

                .append(true)

                .open(
                    &self.file_path
                )

        {

            let _ = writeln!(
                file,
                "{},{},{},{},{},{},{},{},{},{},{:.2},{},{},{},{:.4},{}",

                window
                    .start_time
                    .to_rfc3339(),

                mac,

                window.connections,

                window.disconnections,

                window.connection_failures,

                window.authentication_failures,

                window.pairing_requests,

                window.advertising_reports,

                window.rssi_updates,

                window.valid_rssi_samples,

                window.average_rssi(),

                window.rssi_range(),

                window.other_events,

                window.total_events,

                connection_disconnect_ratio,

                label,
            );
        }
    }


    /*
     * ========================================================
     * FLUSH EXPIRED WINDOWS
     * ========================================================
     *
     * Called periodically from main.rs.
     */

    pub fn flush_expired(
        &mut self,
    ) {

        let now =
            Utc::now();


        /*
         * Find all expired device windows.
         */

        let expired:

            Vec<String> =

            self.windows
                .iter()

                .filter_map(
                    |(mac, window)| {

                        let age =

                            now
                                .signed_duration_since(
                                    window.start_time
                                )

                                .num_seconds();


                        if age
                            >= self.window_seconds
                        {

                            Some(
                                mac.clone()
                            )

                        } else {

                            None
                        }
                    }
                )

                .collect();


        /*
         * Save each expired window.
         */

        for mac in expired {

            self.flush_device(
                &mac
            );
        }
    }


    /*
     * ========================================================
     * FLUSH ALL REMAINING WINDOWS
     * ========================================================
     *
     * Called when the sensor shuts down.
     */

    pub fn flush_all(
        &mut self,
    ) {

        let devices:

            Vec<String> =

            self.windows
                .keys()
                .cloned()
                .collect();


        for mac in devices {

            self.flush_device(
                &mac
            );
        }
    }
}