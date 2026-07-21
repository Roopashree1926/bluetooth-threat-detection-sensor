use tokio::process::Command;

use crate::models::incident::{
    IncidentStatus,
    SecurityIncident,
};


pub struct PreventionEngine {

    /*
     * Master switch for active prevention.
     */
    enabled: bool,

    /*
     * During project testing, active containment
     * is restricted to one explicitly authorized
     * Bluetooth test device.
     */
    authorized_test_mac:
        String,
}


impl PreventionEngine {

    pub fn new(
        enabled: bool,
        authorized_test_mac: &str,
    ) -> Self {

        Self {

            enabled,

            authorized_test_mac:
                authorized_test_mac
                    .to_uppercase(),
        }
    }


    /*
     * ========================================================
     * RESPOND TO SOC INCIDENT
     * ========================================================
     *
     * IMPORTANT:
     *
     * SecurityAlert cannot directly call containment.
     *
     * Only a SOC-approved SecurityIncident reaches here.
     */

    pub async fn respond(
        &self,
        incident: &SecurityIncident,
    ) -> bool {

        /*
         * ----------------------------------------------------
         * PREVENTION ENABLED?
         * ----------------------------------------------------
         */

        if !self.enabled {

            return false;
        }


        /*
         * ----------------------------------------------------
         * SOC APPROVAL REQUIRED
         * ----------------------------------------------------
         */

        if incident.status
            != IncidentStatus::Approved
        {

            /*
             * Pending or rejected incidents
             * cannot trigger containment.
             */

            return false;
        }


        /*
         * ----------------------------------------------------
         * DEVICE MAC REQUIRED
         * ----------------------------------------------------
         */

        let Some(mac) =
            incident.device_mac.as_ref()

        else {

            return false;
        };


        let normalized_mac =
            mac.to_uppercase();


        /*
         * ----------------------------------------------------
         * AUTHORIZED TEST DEVICE SAFETY CHECK
         * ----------------------------------------------------
         *
         * Active containment is restricted to
         * the explicitly configured lab/test device.
         */

        if normalized_mac
            != self.authorized_test_mac
        {

            return false;
        }


        /*
         * ----------------------------------------------------
         * CONTAINMENT POLICY
         * ----------------------------------------------------
         */

        let containment_allowed =
            matches!(

                incident
                    .threat_name
                    .as_str(),

                "Suspicious Connection Cycling"

                | "Reconnection Flood"

                | "Authentication Brute Force"

                | "Encryption Downgrade"

                | "Repeated Connection Failure"
            );


        if !containment_allowed {

            return false;
        }


        /*
         * ====================================================
         * STEP 1 — DISCONNECT
         * ====================================================
         */

        let disconnect_result =

            Command::new(
                "bluetoothctl"
            )

            .arg(
                "disconnect"
            )

            .arg(
                &normalized_mac
            )

            .status()

            .await;


        let disconnected =
            matches!(

                disconnect_result,

                Ok(status)
                    if status.success()
            );


        /*
         * ====================================================
         * STEP 2 — BLOCK
         * ====================================================
         *
         * Only attempt blocking after the disconnect command
         * completed successfully.
         */

        if !disconnected {

            return false;
        }


        let block_result =

            Command::new(
                "bluetoothctl"
            )

            .arg(
                "block"
            )

            .arg(
                &normalized_mac
            )

            .status()

            .await;


        matches!(

            block_result,

            Ok(status)
                if status.success()
        )
    }
}