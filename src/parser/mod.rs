pub mod packet_builder;

use chrono::Utc;
use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::models::{
    BluetoothEvent,
    EventType,
};

static BUILDER: Lazy<Mutex<packet_builder::PacketBuilder>> =
    Lazy::new(|| {
        Mutex::new(
            packet_builder::PacketBuilder::new()
        )
    });


pub fn parse_line(
    line: &str,
) -> Option<BluetoothEvent> {

    /*
     * ========================================================
     * BUILD COMPLETE BTMON PACKET
     * ========================================================
     */

    let mut builder =
        BUILDER.lock().unwrap();

    let packet =
        builder.push_line(line)?;


    /*
     * ========================================================
     * CLASSIFY BLUETOOTH EVENT
     * ========================================================
     *
     * IMPORTANT:
     *
     * Order matters.
     *
     * More specific/security-important events are checked
     * before generic RSSI events.
     */


    let event_type =

        /*
         * ====================================================
         * ADVERTISING EVENTS
         * ====================================================
         *
         * Real btmon examples:
         *
         * LE Advertising Report
         * LE Extended Advertising Report
         * LE Direct Advertising Report
         * LE Periodic Advertising Report
         */

        if packet
            .raw_data
            .contains(
                "LE Extended Advertising Report"
            )

            || packet
                .raw_data
                .contains(
                    "LE Advertising Report"
                )

            || packet
                .raw_data
                .contains(
                    "LE Direct Advertising Report"
                )

            || packet
                .raw_data
                .contains(
                    "LE Periodic Advertising Report"
                )
        {

            EventType::AdvertisingReport
        }


        /*
         * ====================================================
         * DISCONNECTION EVENTS
         * ====================================================
         *
         * Your real btmon output contains:
         *
         * > HCI Event: Disconnect Complete
         *
         * and:
         *
         * @ MGMT Event: Device Disconnected
         *
         * Some BlueZ versions may use:
         *
         * Disconnection Complete
         */

        else if packet
            .raw_data
            .contains(
                "Disconnect Complete"
            )

            || packet
                .raw_data
                .contains(
                    "Disconnection Complete"
                )

            || packet
                .raw_data
                .contains(
                    "Device Disconnected"
                )
        {

            EventType::DisconnectionComplete
        }


        /*
         * ====================================================
         * CONNECTION RE-ESTABLISHMENT
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Connection Reestablished"
            )

            || packet
                .raw_data
                .contains(
                    "Connection Re-established"
                )

            || packet
                .raw_data
                .contains(
                    "Reconnection Complete"
                )
        {

            EventType::ConnectionReestablished
        }


        /*
         * ====================================================
         * SUCCESSFUL CONNECTION
         * ====================================================
         *
         * IMPORTANT FIX:
         *
         * Your actual btmon output uses:
         *
         * > HCI Event: Connect Complete
         *
         * NOT only:
         *
         * Connection Complete
         *
         * MGMT also produces:
         *
         * @ MGMT Event: Device Connected
         */

        else if packet
            .raw_data
            .contains(
                "Connect Complete"
            )

            || packet
                .raw_data
                .contains(
                    "Connection Complete"
                )

            || packet
                .raw_data
                .contains(
                    "LE Connection Complete"
                )

            || packet
                .raw_data
                .contains(
                    "LE Enhanced Connection Complete"
                )

            || packet
                .raw_data
                .contains(
                    "Device Connected"
                )
        {

            EventType::ConnectionComplete
        }


        /*
         * ====================================================
         * AUTHENTICATION FAILURE
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Authentication Failed"
            )

            ||

            (
                packet
                    .raw_data
                    .contains(
                        "Authentication Complete"
                    )

                &&

                !packet
                    .raw_data
                    .contains(
                        "Status: Success"
                    )
            )
        {

            EventType::AuthenticationFailed
        }


        /*
         * ====================================================
         * SUCCESSFUL AUTHENTICATION
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Authentication Complete"
            )
        {

            EventType::AuthenticationComplete
        }


        /*
         * ====================================================
         * PAIRING REQUEST
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Pairing Request"
            )
        {

            EventType::PairingRequest
        }


        /*
         * ====================================================
         * PAIRING COMPLETE
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Simple Pairing Complete"
            )

            || packet
                .raw_data
                .contains(
                    "Pairing Complete"
                )
        {

            EventType::PairingComplete
        }


        /*
         * ====================================================
         * ENCRYPTION DOWNGRADE
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Encryption Downgrade"
            )

            || packet
                .raw_data
                .contains(
                    "Legacy Secure Connections"
                )
        {

            EventType::EncryptionDowngrade
        }


        /*
         * ====================================================
         * ENCRYPTION KEY SIZE
         * ====================================================
         */

        else if packet
            .key_size
            .is_some()
        {

            EventType::EncryptionKeySize
        }


        /*
         * ====================================================
         * ENCRYPTION STATE CHANGE
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Encryption Change"
            )

            || packet
                .raw_data
                .contains(
                    "Encryption: Enabled"
                )

            || packet
                .raw_data
                .contains(
                    "Encryption: Disabled"
                )
        {

            EventType::EncryptionChange
        }


        /*
         * ====================================================
         * ROLE CHANGE
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Role Change"
            )

            || packet
                .raw_data
                .contains(
                    "Role Switch"
                )
        {

            EventType::RoleChange
        }


        /*
         * ====================================================
         * L2CAP CONNECTION REQUEST
         * ====================================================
         *
         * Real btmon:
         *
         * L2CAP: Connection Request
         */

        else if packet
            .raw_data
            .contains(
                "L2CAP: Connection Request"
            )

            || packet
                .raw_data
                .contains(
                    "L2CAP Connection Request"
                )

            ||

            (
                packet
                    .raw_data
                    .contains(
                        "Connection Request"
                    )

                &&

                packet
                    .raw_data
                    .contains(
                        "L2CAP"
                    )
            )
        {

            EventType::L2CAPConnectionRequest
        }


        /*
         * ====================================================
         * L2CAP CHANNEL OPEN
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "L2CAP Channel Open"
            )

            ||

            (
                packet
                    .raw_data
                    .contains(
                        "Channel Open"
                    )

                &&

                packet
                    .raw_data
                    .contains(
                        "L2CAP"
                    )
            )
        {

            EventType::L2CAPChannelOpen
        }


        /*
         * ====================================================
         * L2CAP CHANNEL CLOSE
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "L2CAP Channel Close"
            )

            ||

            (
                packet
                    .raw_data
                    .contains(
                        "Channel Close"
                    )

                &&

                packet
                    .raw_data
                    .contains(
                        "L2CAP"
                    )
            )
        {

            EventType::L2CAPChannelClose
        }


        /*
         * ====================================================
         * IO CAPABILITY REQUEST
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "IO Capability Request"
            )
        {

            EventType::IOCapabilityRequest
        }


        /*
         * ====================================================
         * USER CONFIRMATION REQUEST
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "User Confirmation Request"
            )
        {

            EventType::UserConfirmationRequest
        }


        /*
         * ====================================================
         * PASSKEY REQUEST
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "User Passkey Request"
            )

            || packet
                .raw_data
                .contains(
                    "Passkey Request"
                )
        {

            EventType::PasskeyRequest
        }


        /*
         * ====================================================
         * DEVICE FOUND
         * ====================================================
         *
         * Your real btmon output contains:
         *
         * @ MGMT Event: Device Found
         */

        else if packet
            .raw_data
            .contains(
                "Device Found"
            )
        {

            EventType::DeviceFound
        }


        /*
         * ====================================================
         * DEVICE LOST
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Device Lost"
            )
        {

            EventType::DeviceLost
        }


        /*
         * ====================================================
         * SERVICE DISCOVERY
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Service Discovery"
            )

            || packet
                .raw_data
                .contains(
                    "Service Search"
                )

            || packet
                .raw_data
                .contains(
                    "Read By Group Type"
                )
        {

            EventType::ServiceDiscovery
        }


        /*
         * ====================================================
         * HCI ERROR
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Hardware Error"
            )

            || packet
                .raw_data
                .contains(
                    "HCI Error"
                )
        {

            EventType::HCIError
        }


        /*
         * ====================================================
         * VENDOR-SPECIFIC EVENT
         * ====================================================
         */

        else if packet
            .raw_data
            .contains(
                "Vendor Specific"
            )

            || packet
                .raw_data
                .contains(
                    "Vendor-specific"
                )
        {

            EventType::VendorSpecificEvent
        }


        /*
         * ====================================================
         * RSSI UPDATE
         * ====================================================
         *
         * Keep near the end.
         *
         * Many important packets also contain RSSI.
         * We do not want RSSI to override a connection,
         * discovery or security event.
         */

        else if packet
            .rssi
            .is_some()
        {

            EventType::RSSIUpdate
        }


        /*
         * ====================================================
         * UNKNOWN EVENT
         * ====================================================
         */

        else {

            EventType::Unknown
        };


    /*
     * ========================================================
     * ENCRYPTION DOWNGRADE SAFETY CHECK
     * ========================================================
     *
     * If encryption key size is below 7 octets,
     * classify it as a possible encryption downgrade.
     */

    let event_type =
        match packet.key_size {

            Some(key_size)
                if key_size < 7 =>
            {

                EventType::EncryptionDowngrade
            }

            _ => event_type,
        };


    /*
     * ========================================================
     * CREATE BLUETOOTH EVENT
     * ========================================================
     */

    Some(
        BluetoothEvent {

            timestamp:
                Utc::now(),

            event_type,

            mac:
                Some(
                    packet.mac
                ),

            device_name:
                packet.name,

            rssi:
                packet.rssi,

            hci_interface:
                Some(
                    "hci0".to_string()
                ),

            connection_handle:
                packet.connection_handle,

            role:
                packet.role,

            encryption_enabled:
                packet.encryption_enabled,

            key_size:
                packet.key_size,

            l2cap_cid:
                packet.l2cap_cid,

            service_uuid:
                packet.service_uuid,

            hci_event_code:
                packet.hci_event_code,

            raw_line:
                packet.raw_data,
        }
    )
}