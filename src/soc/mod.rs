use std::collections::HashMap;

use std::sync::atomic::{
    AtomicUsize,
    Ordering,
};

use chrono::Utc;

use crate::models::alert::SecurityAlert;

use crate::models::incident::{
    IncidentStatus,
    SecurityIncident,
};


/*
 * ============================================================
 * GLOBAL INCIDENT COUNTER
 * ============================================================
 *
 * Generates:
 *
 * INC-0001
 * INC-0002
 * INC-0003
 * ...
 */

static INCIDENT_COUNTER: AtomicUsize =
    AtomicUsize::new(1);


/*
 * ============================================================
 * SOC INCIDENT MANAGER
 * ============================================================
 *
 * Responsibilities:
 *
 * 1. Create incidents from security alerts
 * 2. Store incidents
 * 3. Allow SOC approval
 * 4. Allow SOC rejection
 * 5. Mark incidents for continued monitoring
 * 6. Mark false positives
 *
 * IMPORTANT:
 *
 * Creating an incident NEVER blocks a Bluetooth device.
 *
 * Prevention is allowed only after the incident
 * becomes Approved.
 */

pub struct IncidentManager {

    /*
     * Incident storage.
     *
     * Example:
     *
     * "INC-0001" -> SecurityIncident
     */

    incidents:
        HashMap<String, SecurityIncident>,
}


impl IncidentManager {

    /*
     * ========================================================
     * CREATE INCIDENT MANAGER
     * ========================================================
     */

    pub fn new() -> Self {

        Self {

            incidents:
                HashMap::new(),
        }
    }


    /*
     * ========================================================
     * CREATE SOC INCIDENT
     * ========================================================
     *
     * Flow:
     *
     * SecurityAlert
     *      ↓
     * SecurityIncident
     *      ↓
     * PendingSocReview
     *
     * No prevention occurs here.
     */

    pub fn create_incident(
        &mut self,
        alert: &SecurityAlert,
    ) -> SecurityIncident {

        /*
         * Generate incident number.
         */

        let number =

            INCIDENT_COUNTER
                .fetch_add(

                    1,

                    Ordering::Relaxed,
                );


        /*
         * Generate ID.
         *
         * Example:
         *
         * INC-0001
         */

        let incident_id =

            format!(
                "INC-{:04}",
                number
            );


        /*
         * Create incident.
         */

        let incident =

            SecurityIncident {

                id:
                    incident_id.clone(),

                created_at:
                    Utc::now(),

                threat_name:
                    alert.name.clone(),

                severity:
                    alert.severity.clone(),

                device_mac:
                    alert.mac.clone(),

                details:
                    alert.details.clone(),

                /*
                 * Every new incident starts here.
                 */

                status:
                    IncidentStatus::PendingSocReview,
            };


        /*
         * Store incident.
         *
         * This allows SOC to review it later using:
         *
         * approve INC-0001
         *
         * reject INC-0001
         *
         * etc.
         */

        self.incidents.insert(

            incident_id,

            incident.clone(),
        );


        /*
         * Return incident to main.rs.
         */

        incident
    }


    /*
     * ========================================================
     * GET INCIDENT
     * ========================================================
     *
     * Retrieve an incident without changing it.
     */

    pub fn get_incident(
        &self,
        id: &str,
    ) -> Option<&SecurityIncident> {

        self.incidents.get(id)
    }


    /*
     * ========================================================
     * APPROVE INCIDENT
     * ========================================================
     *
     * SOC has reviewed the evidence and confirmed
     * that containment is authorized.
     *
     * PendingSocReview
     *        ↓
     *     Approved
     *
     * Only Approved incidents can reach active prevention.
     */

    pub fn approve(
        &mut self,
        id: &str,
    ) -> Option<SecurityIncident> {

        let incident =

            self.incidents
                .get_mut(id)?;


        /*
         * Only incidents waiting for SOC review or
         * being monitored should normally be approved.
         */

        match incident.status {

            IncidentStatus::PendingSocReview
            | IncidentStatus::Monitoring => {

                incident.status =
                    IncidentStatus::Approved;
            }


            /*
             * Already approved.
             *
             * Keep current state.
             */

            IncidentStatus::Approved => {}


            /*
             * Rejected or false-positive incidents
             * should not silently become approved.
             */

            IncidentStatus::Rejected
            | IncidentStatus::FalsePositive => {

                return None;
            }
        }


        Some(
            incident.clone()
        )
    }


    /*
     * ========================================================
     * REJECT INCIDENT
     * ========================================================
     *
     * SOC determines that containment should NOT occur.
     */

    pub fn reject(
        &mut self,
        id: &str,
    ) -> Option<SecurityIncident> {

        let incident =

            self.incidents
                .get_mut(id)?;


        /*
         * Do not allow an already approved incident
         * to be silently changed after containment
         * may have started.
         */

        if incident.status
            == IncidentStatus::Approved
        {

            return None;
        }


        incident.status =
            IncidentStatus::Rejected;


        Some(
            incident.clone()
        )
    }


    /*
     * ========================================================
     * MONITOR INCIDENT
     * ========================================================
     *
     * SOC is not ready to approve containment.
     *
     * Continue observing the device.
     *
     * No blocking occurs.
     */

    pub fn monitor(
        &mut self,
        id: &str,
    ) -> Option<SecurityIncident> {

        let incident =

            self.incidents
                .get_mut(id)?;


        /*
         * Only pending/monitoring incidents can remain
         * under observation.
         */

        match incident.status {

            IncidentStatus::PendingSocReview
            | IncidentStatus::Monitoring => {

                incident.status =
                    IncidentStatus::Monitoring;
            }


            _ => {

                return None;
            }
        }


        Some(
            incident.clone()
        )
    }


    /*
     * ========================================================
     * FALSE POSITIVE
     * ========================================================
     *
     * SOC determines the detected behavior was legitimate.
     *
     * Example:
     *
     * A genuine headset repeatedly reconnecting because
     * of temporary signal problems.
     *
     * No containment occurs.
     */

    pub fn false_positive(
        &mut self,
        id: &str,
    ) -> Option<SecurityIncident> {

        let incident =

            self.incidents
                .get_mut(id)?;


        /*
         * An already approved incident should not
         * silently become a false positive after
         * prevention may have started.
         */

        if incident.status
            == IncidentStatus::Approved
        {

            return None;
        }


        incident.status =
            IncidentStatus::FalsePositive;


        Some(
            incident.clone()
        )
    }


    /*
     * ========================================================
     * CHECK SOC APPROVAL
     * ========================================================
     *
     * Returns true ONLY when SOC has explicitly approved
     * the incident.
     */

    pub fn is_approved(
        &self,
        incident: &SecurityIncident,
    ) -> bool {

        incident.status
            == IncidentStatus::Approved
    }
}