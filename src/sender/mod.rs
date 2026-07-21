use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::models::security_event::SecurityEvent;

pub struct EventSender;

impl EventSender {
    pub fn new() -> Self {
        Self
    }

    /*
     * ========================================================
     * Generate Next Event ID
     * ========================================================
     *
     * events/
     *
     * BT_EVT_000001.json
     * BT_EVT_000002.json
     * BT_EVT_000003.json
     *
     * Next:
     *
     * BT_EVT_000004
     */

    fn next_event_id(&self) -> String {
        let mut max_id: u32 = 0;

        if Path::new("events").exists() {
            if let Ok(entries) = fs::read_dir("events") {
                for entry in entries.flatten() {
                    let file_name = entry.file_name();

                    if let Some(name) = file_name.to_str() {
                        if name.starts_with("BT_EVT_")
                            && name.ends_with(".json")
                        {
                            let number = name
                                .trim_start_matches("BT_EVT_")
                                .trim_end_matches(".json");

                            if let Ok(value) = number.parse::<u32>() {
                                if value > max_id {
                                    max_id = value;
                                }
                            }
                        }
                    }
                }
            }
        }

        format!("BT_EVT_{:06}", max_id + 1)
    }

    /*
     * ========================================================
     * Send Security Event
     * ========================================================
     */

    pub fn send(
        &self,
        event: &SecurityEvent,
    ) -> Result<()> {

        /*
         * Create events directory.
         */

        if !Path::new("events").exists() {
            fs::create_dir_all("events")?;
        }

        /*
         * Generate unique Event ID.
         */

        let event_id = self.next_event_id();

        /*
         * Clone event so we don't modify the original.
         */

        let mut event_copy = event.clone();

        event_copy.event_id = event_id.clone();

        /*
         * Output filename.
         */

        let file_path = format!(
            "events/{}.json",
            event_id
        );

        /*
         * Serialize JSON.
         */

        let json =
            serde_json::to_string_pretty(&event_copy)?;

        /*
         * Save JSON.
         */

        fs::write(
            &file_path,
            json,
        )?;

        /*
         * Display confirmation.
         */

        println!();

        println!("============================================================");
        println!("               SECURITY EVENT GENERATED");
        println!("============================================================");

        println!("Event ID     : {}", event_copy.event_id);
        println!("Incident ID  : {}", event_copy.soc_incident);
        println!("Threat       : {}", event_copy.event_type);
        println!("Severity     : {}", event_copy.severity);
        println!("Confidence   : {}%", event_copy.confidence);
        println!("Destination  : {}", file_path);
        println!("Status       : READY FOR IDSM");
        println!("============================================================");

        Ok(())
    }
    pub fn update(
    &self,
    incident: &crate::models::incident::SecurityIncident,
) -> anyhow::Result<()> {

    use std::fs;

    let entries = fs::read_dir("events")?;

    for entry in entries {

        let path = entry?.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let text = fs::read_to_string(&path)?;

        let mut event: crate::models::security_event::SecurityEvent =
            serde_json::from_str(&text)?;

        /*
         * Match this incident.
         */

        if event.soc_incident == incident.id {

            event.soc_status =
                format!("{:?}", incident.status);

            /*
             * Update action hint.
             */

            event.action_hint = match incident.status {

                crate::models::incident::IncidentStatus::Approved => {

                    "contain_device".to_string()
                }

                crate::models::incident::IncidentStatus::Rejected => {

                    "no_action".to_string()
                }

                crate::models::incident::IncidentStatus::Monitoring => {

                    "continue_monitoring".to_string()
                }

                crate::models::incident::IncidentStatus::FalsePositive => {

                    "allow_device".to_string()
                }

                crate::models::incident::IncidentStatus::PendingSocReview => {

                    "log_and_alert".to_string()
                }

            };

            fs::write(

                &path,

                serde_json::to_string_pretty(&event)?,

            )?;

            println!();
            println!("==================================================");
            println!("EVENT UPDATED");
            println!("Incident : {}", incident.id);
            println!("Status   : {:?}", incident.status);
            println!("File     : {}", path.display());
            println!("==================================================");

            break;
        }
    }

    Ok(())
}
}