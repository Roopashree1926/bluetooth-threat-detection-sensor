use chrono::Local;

use std::collections::HashSet;
use std::io::{self, Write};

use crate::models::{
    BluetoothEvent,
    EventType,
};

pub struct Dashboard {

    /*
     * Total parsed Bluetooth packets/events.
     */
    packets: usize,

    /*
     * Advertising reports observed.
     */
    advertising: usize,

    /*
     * Number of genuine connection transitions
     * during this monitoring session.
     */
    connection_sessions: usize,

    /*
     * Number of genuine disconnection transitions.
     */
    disconnections: usize,

    /*
     * Unique devices discovered.
     */
    discovered_devices: HashSet<String>,

    /*
     * Devices currently connected.
     *
     * HashSet prevents duplicate connection events
     * for the same MAC from being counted multiple times.
     */
    connected_devices: HashSet<String>,

    rssi_updates: usize,

    authentication_failures: usize,

    pairing_requests: usize,

    threats: usize,

    latest_threat: String,

    latest_incident: String,

    incident_status: String,
}


impl Dashboard {

    pub fn new() -> Self {

        Self {

            packets: 0,

            advertising: 0,

            connection_sessions: 0,

            disconnections: 0,

            discovered_devices:
                HashSet::new(),

            connected_devices:
                HashSet::new(),

            rssi_updates: 0,

            authentication_failures: 0,

            pairing_requests: 0,

            threats: 0,

            latest_threat:
                "None".to_string(),

            latest_incident:
                "None".to_string(),

            incident_status:
                "None".to_string(),
        }
    }


    /*
     * ========================================================
     * PROCESS BLUETOOTH EVENT
     * ========================================================
     */

    pub fn update(
        &mut self,
        event: &BluetoothEvent,
    ) {

        self.packets += 1;


        match &event.event_type {

            /*
             * ------------------------------------------------
             * ADVERTISING
             * ------------------------------------------------
             */

            EventType::AdvertisingReport => {

                self.advertising += 1;

                /*
                 * Advertising can also reveal a device.
                 *
                 * Add its MAC to discovered devices
                 * if a valid MAC is available.
                 */

                if let Some(mac) =
                    Self::valid_mac(event)
                {

                    self.discovered_devices
                        .insert(mac);
                }
            }


            /*
             * ------------------------------------------------
             * CONNECTION
             * ------------------------------------------------
             *
             * btmon can generate multiple events for one
             * physical connection:
             *
             * Connect Complete
             * Device Connected
             *
             * We count the connection only when the MAC
             * changes from:
             *
             * NOT CONNECTED -> CONNECTED
             */

            EventType::ConnectionComplete => {

                if let Some(mac) =
                    Self::valid_mac(event)
                {

                    /*
                     * A connected device is also a known device.
                     */

                    self.discovered_devices
                        .insert(mac.clone());


                    /*
                     * HashSet::insert returns:
                     *
                     * true  = MAC was not previously connected
                     * false = MAC was already connected
                     */

                    let newly_connected =
                        self.connected_devices
                            .insert(mac);


                    /*
                     * Increment only for a genuine new
                     * connection state transition.
                     */

                    if newly_connected {

                        self.connection_sessions += 1;
                    }
                }
            }


            /*
             * ------------------------------------------------
             * DISCONNECTION
             * ------------------------------------------------
             *
             * btmon may generate:
             *
             * Disconnect Complete
             * Device Disconnected
             *
             * for the same physical disconnection.
             *
             * HashSet::remove ensures it is counted once.
             */

            EventType::DisconnectionComplete => {

                if let Some(mac) =
                    Self::valid_mac(event)
                {

                    /*
                     * remove() returns true only if the
                     * device was actually marked connected.
                     */

                    let was_connected =
                        self.connected_devices
                            .remove(&mac);


                    if was_connected {

                        self.disconnections += 1;
                    }
                }
            }


            /*
             * ------------------------------------------------
             * DEVICE DISCOVERY
             * ------------------------------------------------
             *
             * The same device may generate many Device Found
             * events while scanning.
             *
             * Count unique MAC addresses only.
             */

            EventType::DeviceFound => {

                if let Some(mac) =
                    Self::valid_mac(event)
                {

                    self.discovered_devices
                        .insert(mac);
                }
            }


            /*
             * ------------------------------------------------
             * RSSI
             * ------------------------------------------------
             */

            EventType::RSSIUpdate => {

                self.rssi_updates += 1;
            }


            /*
             * ------------------------------------------------
             * AUTHENTICATION FAILURE
             * ------------------------------------------------
             */

            EventType::AuthenticationFailed => {

                self.authentication_failures += 1;
            }


            /*
             * ------------------------------------------------
             * PAIRING REQUEST
             * ------------------------------------------------
             */

            EventType::PairingRequest => {

                self.pairing_requests += 1;
            }


            _ => {}
        }
    }


    /*
     * ========================================================
     * VALID MAC ADDRESS
     * ========================================================
     *
     * parser currently uses "Unknown" when no MAC is available.
     *
     * We must NOT use "Unknown" as a device identity because
     * multiple unrelated HCI events would otherwise appear
     * to belong to one fake device.
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
     * THREAT DETECTED
     * ========================================================
     */

    pub fn threat(
        &mut self,
        name: &str,
    ) {

        self.threats += 1;

        self.latest_threat =
            name.to_string();
    }


    /*
     * ========================================================
     * SOC INCIDENT
     * ========================================================
     */

    pub fn soc_incident(
        &mut self,
        id: &str,
        status: &str,
    ) {

        self.latest_incident =
            id.to_string();

        self.incident_status =
            status.to_string();
    }


    /*
     * ========================================================
     * SINGLE LIVE DASHBOARD
     * ========================================================
     */

    pub fn display(&self) {

        /*
         * Clear previous dashboard and redraw
         * from the top-left corner.
         */

        print!(
            "\x1B[2J\x1B[3J\x1B[H"
        );


        println!(
            "============================================================"
        );

        println!(
            "        BLUETOOTH THREAT DETECTION SENSOR"
        );

        println!(
            "============================================================"
        );


        println!(
            "System Status   : RUNNING"
        );


        println!(
            "Monitoring Time : {}",
            Local::now()
                .format("%H:%M:%S")
        );


        println!(
            "------------------------------------------------------------"
        );


        println!(
            "Packets Captured            : {}",
            self.packets
        );


        println!(
            "Advertising Reports         : {}",
            self.advertising
        );


        /*
         * Number of unique MAC addresses currently
         * marked as connected.
         */

        println!(
            "Currently Connected Devices : {}",
            self.connected_devices.len()
        );


        /*
         * Number of genuine disconnected -> connected
         * transitions observed during this session.
         */

        println!(
            "Connection Sessions         : {}",
            self.connection_sessions
        );


        println!(
            "Disconnections              : {}",
            self.disconnections
        );


        println!(
            "Unique Devices Found        : {}",
            self.discovered_devices.len()
        );


        println!(
            "RSSI Updates                : {}",
            self.rssi_updates
        );


        println!(
            "Authentication Failures     : {}",
            self.authentication_failures
        );


        println!(
            "Pairing Requests            : {}",
            self.pairing_requests
        );


        println!(
            "------------------------------------------------------------"
        );


        println!(
            "Threats Detected : {}",
            self.threats
        );


        println!(
            "Latest Threat    : {}",
            self.latest_threat
        );


        /*
         * Display SOC section only after
         * an incident has been created.
         */

        if self.latest_incident != "None" {

            println!(
                "------------------------------------------------------------"
            );


            println!(
                "Latest SOC Incident : {}",
                self.latest_incident
            );


            println!(
                "SOC Status          : {}",
                self.incident_status
            );
        }


        println!(
            "============================================================"
        );


        println!(
            "Monitoring Bluetooth Traffic..."
        );


        println!(
            "============================================================"
        );


        io::stdout()
            .flush()
            .unwrap();
    }
}