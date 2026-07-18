use once_cell::sync::Lazy;
use regex::Regex;

use crate::models::BluetoothPacket;


/*
 * Compile regex patterns only once.
 *
 * This is more efficient for continuous real-time monitoring.
 */

static MAC_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)([0-9A-F]{2}(?::[0-9A-F]{2}){5})"
    )
    .unwrap()
});

static RSSI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)RSSI:\s*(-?\d+)"
    )
    .unwrap()
});

static HANDLE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)Handle:\s*(\d+)"
    )
    .unwrap()
});

static KEY_SIZE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)Key\s+Size:\s*(\d+)"
    )
    .unwrap()
});

static CID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)CID:\s*(0x[0-9A-F]+|\d+)"
    )
    .unwrap()
});

static EVENT_CODE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\((0x[0-9A-Fa-f]+)\)"
    )
    .unwrap()
});


pub struct PacketBuilder {

    current_mac: Option<String>,

    current_name: Option<String>,

    current_rssi: Option<i16>,

    current_connection_handle: Option<u16>,

    current_role: Option<String>,

    current_encryption_enabled: Option<bool>,

    current_key_size: Option<u8>,

    current_l2cap_cid: Option<u16>,

    current_service_uuid: Option<String>,

    current_hci_event_code: Option<String>,

    current_data: Vec<String>,
}


impl PacketBuilder {

    pub fn new() -> Self {

        Self {

            current_mac: None,

            current_name: None,

            current_rssi: None,

            current_connection_handle: None,

            current_role: None,

            current_encryption_enabled: None,

            current_key_size: None,

            current_l2cap_cid: None,

            current_service_uuid: None,

            current_hci_event_code: None,

            current_data: Vec::new(),
        }
    }


    /*
     * ========================================================
     * RECEIVE ONE BTMON LINE
     * ========================================================
     */

    pub fn push_line(
        &mut self,
        line: &str,
    ) -> Option<BluetoothPacket> {

        /*
         * Remove only leading/trailing whitespace for
         * event-boundary detection.
         *
         * Keep original line for raw_data.
         */

        let trimmed =
            line.trim();


        /*
         * Detect whether this line starts a new top-level
         * btmon record.
         */

        let new_packet =
            Self::is_packet_start(trimmed);


        /*
         * If a new packet begins and we already have data,
         * finish and return the previous packet.
         */

        if new_packet
            && !self.current_data.is_empty()
        {

            let previous_packet =
                self.build_current_packet();


            /*
             * Start collecting the new packet.
             */

            self.reset_packet_fields();

            self.current_data.clear();

            self.current_data.push(
                line.to_string()
            );


            /*
             * Parse information contained directly
             * in the first line.
             */

            self.extract_fields(
                trimmed
            );


            return Some(
                previous_packet
            );
        }


        /*
         * Add current line to active packet.
         */

        self.current_data.push(
            line.to_string()
        );


        /*
         * Extract telemetry.
         */

        self.extract_fields(
            trimmed
        );


        None
    }


    /*
     * ========================================================
     * DETECT BTMON PACKET BOUNDARY
     * ========================================================
     */

    fn is_packet_start(
        line: &str,
    ) -> bool {

        /*
         * HCI events sent from controller to host.
         */

        line.starts_with(
            "> HCI Event:"
        )

        ||

        /*
         * HCI commands sent from host to controller.
         */

        line.starts_with(
            "< HCI Command:"
        )

        ||

        /*
         * ACL packets.
         *
         * btmon may display:
         *
         * > ACL Data RX:
         * < ACL Data TX:
         */

        line.starts_with(
            "> ACL Data"
        )

        ||

        line.starts_with(
            "< ACL Data"
        )

        ||

        /*
         * SCO traffic.
         */

        line.starts_with(
            "> SCO Data"
        )

        ||

        line.starts_with(
            "< SCO Data"
        )

        ||

        /*
         * ISO traffic.
         */

        line.starts_with(
            "> ISO Data"
        )

        ||

        line.starts_with(
            "< ISO Data"
        )

        ||

        /*
         * BlueZ Management events.
         */

        line.starts_with(
            "@ MGMT Event:"
        )

        ||

        line.contains(
            "@ MGMT Command:"
        )
    }


    /*
     * ========================================================
     * BUILD COMPLETED PACKET
     * ========================================================
     */

    fn build_current_packet(
        &mut self,
    ) -> BluetoothPacket {

        BluetoothPacket {

            mac:
                self.current_mac
                    .take()
                    .unwrap_or_else(
                        || "Unknown".to_string()
                    ),

            name:
                self.current_name.take(),

            rssi:
                self.current_rssi.take(),

            connection_handle:
                self.current_connection_handle.take(),

            role:
                self.current_role.take(),

            encryption_enabled:
                self.current_encryption_enabled.take(),

            key_size:
                self.current_key_size.take(),

            l2cap_cid:
                self.current_l2cap_cid.take(),

            service_uuid:
                self.current_service_uuid.take(),

            hci_event_code:
                self.current_hci_event_code.take(),

            raw_data:
                self.current_data.join(
                    "\n"
                ),
        }
    }


    /*
     * ========================================================
     * EXTRACT PACKET INFORMATION
     * ========================================================
     */

    fn extract_fields(
        &mut self,
        line: &str,
    ) {

        /*
         * ----------------------------------------------------
         * MAC ADDRESS
         * ----------------------------------------------------
         */

        if let Some(cap) =
            MAC_REGEX.captures(line)
        {

            if let Some(value) =
                cap.get(1)
            {

                self.current_mac =
                    Some(
                        value
                            .as_str()
                            .to_uppercase()
                    );
            }
        }


        /*
         * ----------------------------------------------------
         * RSSI
         * ----------------------------------------------------
         */

        if let Some(cap) =
            RSSI_REGEX.captures(line)
        {

            self.current_rssi =
                cap[1]
                    .parse::<i16>()
                    .ok();
        }


        /*
         * ----------------------------------------------------
         * DEVICE NAME
         * ----------------------------------------------------
         */

        if let Some(
            (_, value)
        ) =
            line.split_once(
                "Name (complete):"
            )
        {

            let name =
                value.trim();

            if !name.is_empty() {

                self.current_name =
                    Some(
                        name.to_string()
                    );
            }
        }


        /*
         * Also support MGMT-style Name:
         */

        if self.current_name.is_none()
            && line.trim_start()
                .starts_with("Name:")
        {

            if let Some(
                (_, value)
            ) =
                line.split_once(
                    "Name:"
                )
            {

                let name =
                    value.trim();

                if !name.is_empty() {

                    self.current_name =
                        Some(
                            name.to_string()
                        );
                }
            }
        }


        /*
         * ----------------------------------------------------
         * CONNECTION HANDLE
         * ----------------------------------------------------
         */

        if let Some(cap) =
            HANDLE_REGEX.captures(line)
        {

            self.current_connection_handle =
                cap[1]
                    .parse::<u16>()
                    .ok();
        }


        /*
         * ----------------------------------------------------
         * ROLE
         * ----------------------------------------------------
         */

        if let Some(
            (_, value)
        ) =
            line.split_once(
                "Role:"
            )
        {

            let role =
                value.trim();

            if !role.is_empty() {

                self.current_role =
                    Some(
                        role.to_string()
                    );
            }
        }


        /*
         * ----------------------------------------------------
         * ENCRYPTION STATE
         * ----------------------------------------------------
         */

        if line
            .to_lowercase()
            .contains(
                "encryption:"
            )
        {

            let lower =
                line.to_lowercase();


            if lower.contains(
                "enabled"
            )
                || lower.contains(
                    "encryption: on"
                )
            {

                self.current_encryption_enabled =
                    Some(true);

            }

            else if lower.contains(
                "disabled"
            )
                || lower.contains(
                    "encryption: off"
                )
            {

                self.current_encryption_enabled =
                    Some(false);
            }
        }


        /*
         * ----------------------------------------------------
         * ENCRYPTION KEY SIZE
         * ----------------------------------------------------
         */

        if let Some(cap) =
            KEY_SIZE_REGEX.captures(line)
        {

            self.current_key_size =
                cap[1]
                    .parse::<u8>()
                    .ok();
        }


        /*
         * ----------------------------------------------------
         * L2CAP CID
         * ----------------------------------------------------
         */

        if let Some(cap) =
            CID_REGEX.captures(line)
        {

            let value =
                &cap[1];


            if value
                .to_lowercase()
                .starts_with(
                    "0x"
                )
            {

                self.current_l2cap_cid =
                    u16::from_str_radix(
                        &value[2..],
                        16,
                    )
                    .ok();

            }

            else {

                self.current_l2cap_cid =
                    value
                        .parse::<u16>()
                        .ok();
            }
        }


        /*
         * ----------------------------------------------------
         * SERVICE UUID
         * ----------------------------------------------------
         */

        if let Some(
            (_, value)
        ) =
            line.split_once(
                "UUID:"
            )
        {

            let uuid =
                value.trim();

            if !uuid.is_empty() {

                self.current_service_uuid =
                    Some(
                        uuid.to_string()
                    );
            }
        }


        /*
         * ----------------------------------------------------
         * HCI EVENT CODE
         * ----------------------------------------------------
         */

        if line.starts_with(
            "> HCI Event:"
        )
        {

            if let Some(cap) =
                EVENT_CODE_REGEX
                    .captures(line)
            {

                self.current_hci_event_code =
                    Some(
                        cap[1]
                            .to_string()
                    );
            }
        }
    }


    /*
     * ========================================================
     * RESET PACKET TELEMETRY
     * ========================================================
     */

    fn reset_packet_fields(
        &mut self,
    ) {

        self.current_mac = None;

        self.current_name = None;

        self.current_rssi = None;

        self.current_connection_handle =
            None;

        self.current_role =
            None;

        self.current_encryption_enabled =
            None;

        self.current_key_size =
            None;

        self.current_l2cap_cid =
            None;

        self.current_service_uuid =
            None;

        self.current_hci_event_code =
            None;
    }
}