mod parser;
mod models;
mod detector;
mod event_queue;
mod logger;
mod json_logger;
mod reports;
mod statistics;
mod dashboard;
mod signatures;
mod prevention;
mod soc;
mod ml;

use anyhow::Result;

use tokio::io::{
    AsyncBufReadExt,
    BufReader,
};

use tokio::process::Command;
use tokio::signal;

use tokio::time::{
    interval,
    Duration,
};

use event_queue::EventQueue;


/*
 * ============================================================
 * CONFIGURATION
 * ============================================================
 *
 * Active prevention must only be tested against a Bluetooth
 * device that you own/control.
 */

const AUTHORIZED_TEST_MAC: &str =
    "38:8A:BE:B6:76:CE";


/*
 * SOC command file.
 *
 * Supported:
 *
 * approve INC-0001
 * reject INC-0001
 * monitor INC-0001
 * false-positive INC-0001
 */

const SOC_COMMAND_FILE: &str =
    "soc_command.txt";


/*
 * ML behavioral feature dataset.
 */

const ML_DATASET_FILE: &str =
    "bluetooth_ml_dataset.csv";


/*
 * ============================================================
 * BLUETOOTH THREAT DETECTION SENSOR
 * ============================================================
 *
 *                    Bluetooth Traffic
 *                           |
 *                         btmon
 *                           |
 *                         Parser
 *                           |
 *                    BluetoothEvent
 *                           |
 *             +-------------+-------------+
 *             |                           |
 *             v                           v
 *       Event Queue                ML Feature Collector
 *             |                           |
 *             v                    30-second windows
 *     Signature Detector                  |
 *             |                           v
 *             v                    ML Training Dataset
 *      Security Alert
 *             |
 *             v
 *       SOC Incident
 *             |
 *             v
 *    PENDING SOC REVIEW
 *             |
 *      +------+-------+
 *      |      |       |
 *      v      v       v
 *   Approve Monitor Reject
 *      |
 *      v
 * Prevention Engine
 *      |
 *      v
 * Authorized MAC Check
 *      |
 *      v
 * Disconnect + Block
 */


#[tokio::main]
async fn main() -> Result<()> {

    /*
     * ========================================================
     * ROOT PRIVILEGE CHECK
     * ========================================================
     */

    if unsafe { libc::geteuid() } != 0 {

        eprintln!();

        eprintln!(
            "============================================================"
        );

        eprintln!(
            "ERROR: Bluetooth monitoring requires root privileges."
        );

        eprintln!(
            "============================================================"
        );

        eprintln!();

        eprintln!(
            "Run:"
        );

        eprintln!();

        eprintln!(
            "    cargo build"
        );

        eprintln!(
            "    sudo ./target/debug/sensor"
        );

        eprintln!();

        return Ok(());
    }


    /*
     * ========================================================
     * INITIALIZE SIGNATURE DETECTOR
     * ========================================================
     */

    let mut detector =
        detector::PatternDetector::new();


    /*
     * ========================================================
     * INITIALIZE SOC
     * ========================================================
     */

    let mut incident_manager =
        soc::IncidentManager::new();


    /*
     * ========================================================
     * INITIALIZE PREVENTION ENGINE
     * ========================================================
     *
     * Prevention still requires:
     *
     * 1. SOC Approved incident
     * 2. Authorized MAC
     * 3. Containment-enabled security policy
     */

    let prevention_engine =
        prevention::PreventionEngine::new(

            true,

            AUTHORIZED_TEST_MAC,
        );


    /*
     * ========================================================
     * INITIALIZE EVENT QUEUE
     * ========================================================
     */

    let mut queue =
        EventQueue::new(
            1000
        );


    /*
     * ========================================================
     * INITIALIZE STATISTICS
     * ========================================================
     */

    let mut stats =
        statistics::Statistics::new();


    /*
     * ========================================================
     * INITIALIZE DASHBOARD
     * ========================================================
     */

    let mut dashboard =
        dashboard::Dashboard::new();


    /*
     * ========================================================
     * INITIALIZE ML FEATURE COLLECTOR
     * ========================================================
     *
     * IMPORTANT:
     *
     * This collector now creates behavioral feature windows
     * instead of writing every raw Bluetooth event.
     *
     * Each device gets a 30-second behavioral window.
     */

    let mut ml_collector =
        ml::MLDataCollector::new(
            ML_DATASET_FILE
        );


    /*
     * ========================================================
     * CLEAR OLD SOC COMMAND
     * ========================================================
     */

    let _ =
        tokio::fs::write(

            SOC_COMMAND_FILE,

            "",

        )

        .await;


    /*
     * ========================================================
     * START BTMON
     * ========================================================
     */

    let mut child =

        match Command::new(
            "btmon"
        )

        .stdout(
            std::process::Stdio::piped()
        )

        .stderr(
            std::process::Stdio::piped()
        )

        .spawn()

        {

            Ok(child) => child,


            Err(error) => {

                eprintln!();

                eprintln!(
                    "ERROR: Failed to start btmon."
                );

                eprintln!(
                    "Reason: {}",
                    error
                );

                eprintln!();

                return Ok(());
            }
        };


    /*
     * ========================================================
     * CAPTURE BTMON STDOUT
     * ========================================================
     */

    let stdout =

        child
            .stdout
            .take()

            .expect(
                "Failed to capture btmon stdout"
            );


    /*
     * ========================================================
     * CAPTURE BTMON STDERR
     * ========================================================
     */

    let stderr =

        child
            .stderr
            .take()

            .expect(
                "Failed to capture btmon stderr"
            );


    /*
     * ========================================================
     * ASYNC READERS
     * ========================================================
     */

    let mut reader =

        BufReader::new(
            stdout
        )

        .lines();


    let mut error_reader =

        BufReader::new(
            stderr
        )

        .lines();


    /*
     * ========================================================
     * DASHBOARD TIMER
     * ========================================================
     */

    let mut dashboard_timer =

        interval(
            Duration::from_secs(2)
        );


    /*
     * ========================================================
     * SOC COMMAND TIMER
     * ========================================================
     */

    let mut soc_timer =

        interval(
            Duration::from_secs(2)
        );


    /*
     * Consume Tokio interval's immediate first tick.
     */

    dashboard_timer.tick().await;

    soc_timer.tick().await;


    /*
     * ========================================================
     * INITIAL DASHBOARD
     * ========================================================
     */

    dashboard.display();


    /*
     * ========================================================
     * REAL-TIME MONITORING LOOP
     * ========================================================
     */

    loop {

        tokio::select! {

            /*
             * =================================================
             * RECEIVE REAL BTMON TRAFFIC
             * =================================================
             */

            result = reader.next_line() => {

                match result {

                    /*
                     * -----------------------------------------
                     * BTMON LINE RECEIVED
                     * -----------------------------------------
                     */

                    Ok(Some(line)) => {

                        /*
                         * Parse raw btmon line.
                         */

                        if let Some(event) =

                            parser::parse_line(
                                &line
                            )

                        {

                            /*
                             * =================================
                             * UPDATE DASHBOARD
                             * =================================
                             */

                            dashboard.update(
                                &event
                            );


                            /*
                             * =================================
                             * ML FEATURE COLLECTION
                             * =================================
                             *
                             * The ML collector groups events
                             * by MAC address into behavioral
                             * time windows.
                             *
                             * Unknown MAC events are ignored
                             * by ml/mod.rs.
                             */

                            ml_collector.record_event(
                                &event
                            );


                            /*
                             * =================================
                             * EVENT QUEUE
                             * =================================
                             */

                            queue.push(
                                event
                            );


                            /*
                             * =================================
                             * SIGNATURE DETECTION
                             * =================================
                             */

                            let detected_alerts =

                                detector.process(
                                    queue.recent()
                                );


                            /*
                             * =================================
                             * PROCESS NEW SECURITY ALERTS
                             * =================================
                             */

                            for alert in detected_alerts {

                                /*
                                 * Record threat.
                                 */

                                stats.record(
                                    &alert.name
                                );


                                /*
                                 * Update dashboard.
                                 */

                                dashboard.threat(
                                    &alert.name
                                );


                                /*
                                 * =================================
                                 * CREATE SOC INCIDENT
                                 * =================================
                                 *
                                 * Detection never directly calls
                                 * PreventionEngine.
                                 */

                                let incident =

                                    incident_manager
                                        .create_incident(
                                            &alert
                                        );


                                /*
                                 * New incident waits for SOC.
                                 */

                                dashboard.soc_incident(

                                    &incident.id,

                                    "PENDING SOC REVIEW",
                                );


                                /*
                                 * Immediately display alert.
                                 */

                                dashboard.display();
                            }
                        }
                    }


                    /*
                     * -----------------------------------------
                     * BTMON STOPPED
                     * -----------------------------------------
                     */

                    Ok(None) => {

                        break;
                    }


                    /*
                     * -----------------------------------------
                     * BTMON READ ERROR
                     * -----------------------------------------
                     */

                    Err(error) => {

                        eprintln!();

                        eprintln!(
                            "ERROR reading btmon output: {}",
                            error
                        );

                        break;
                    }
                }
            }


            /*
             * =================================================
             * BTMON ERROR CHANNEL
             * =================================================
             */

            error_result =
                error_reader.next_line() =>
            {

                match error_result {

                    Ok(Some(error_line)) => {

                        if !error_line
                            .trim()
                            .is_empty()
                        {

                            eprintln!();

                            eprintln!(
                                "BTMON ERROR: {}",
                                error_line
                            );
                        }
                    }


                    Ok(None) => {

                        /*
                         * stderr closed.
                         *
                         * stdout branch handles process exit.
                         */
                    }


                    Err(error) => {

                        eprintln!(
                            "Error reading btmon stderr: {}",
                            error
                        );
                    }
                }
            }


            /*
             * =================================================
             * SOC COMMAND PROCESSING
             * =================================================
             */

            _ = soc_timer.tick() => {

                if let Ok(command) =

                    tokio::fs::read_to_string(
                        SOC_COMMAND_FILE
                    )

                    .await

                {

                    let command =

                        command
                            .trim()
                            .to_string();


                    if !command.is_empty() {

                        let parts:
                            Vec<&str> =

                            command
                                .split_whitespace()
                                .collect();


                        /*
                         * Command format:
                         *
                         * ACTION INCIDENT-ID
                         */

                        if parts.len() == 2 {

                            let action =

                                parts[0]
                                    .to_lowercase();


                            let incident_id =

                                parts[1];


                            match action.as_str() {

                                /*
                                 * =============================
                                 * APPROVE
                                 * =============================
                                 */

                                "approve" => {

                                    if let Some(incident) =

                                        incident_manager
                                            .approve(
                                                incident_id
                                            )

                                    {

                                        dashboard.soc_incident(

                                            &incident.id,

                                            "APPROVED - CONTAINMENT AUTHORIZED",
                                        );


                                        dashboard.display();


                                        /*
                                         * =====================
                                         * PREVENTION
                                         * =====================
                                         *
                                         * Only SOC-approved
                                         * incidents reach here.
                                         */

                                        let contained =

                                            prevention_engine
                                                .respond(
                                                    &incident
                                                )

                                                .await;


                                        if contained {

                                            dashboard.soc_incident(

                                                &incident.id,

                                                "APPROVED - DEVICE CONTAINED",
                                            );

                                        } else {

                                            dashboard.soc_incident(

                                                &incident.id,

                                                "APPROVED - CONTAINMENT NOT EXECUTED",
                                            );
                                        }

                                    } else {

                                        eprintln!(
                                            "SOC: Incident {} cannot be approved or was not found.",
                                            incident_id
                                        );
                                    }
                                }


                                /*
                                 * =============================
                                 * REJECT
                                 * =============================
                                 */

                                "reject" => {

                                    if let Some(incident) =

                                        incident_manager
                                            .reject(
                                                incident_id
                                            )

                                    {

                                        dashboard.soc_incident(

                                            &incident.id,

                                            "REJECTED - NO CONTAINMENT",
                                        );

                                    } else {

                                        eprintln!(
                                            "SOC: Incident {} cannot be rejected or was not found.",
                                            incident_id
                                        );
                                    }
                                }


                                /*
                                 * =============================
                                 * MONITOR
                                 * =============================
                                 */

                                "monitor" => {

                                    if let Some(incident) =

                                        incident_manager
                                            .monitor(
                                                incident_id
                                            )

                                    {

                                        dashboard.soc_incident(

                                            &incident.id,

                                            "MONITORING",
                                        );

                                    } else {

                                        eprintln!(
                                            "SOC: Incident {} cannot be monitored or was not found.",
                                            incident_id
                                        );
                                    }
                                }


                                /*
                                 * =============================
                                 * FALSE POSITIVE
                                 * =============================
                                 */

                                "false-positive" => {

                                    if let Some(incident) =

                                        incident_manager
                                            .false_positive(
                                                incident_id
                                            )

                                    {

                                        dashboard.soc_incident(

                                            &incident.id,

                                            "FALSE POSITIVE - DEVICE ALLOWED",
                                        );

                                    } else {

                                        eprintln!(
                                            "SOC: Incident {} cannot be marked false positive or was not found.",
                                            incident_id
                                        );
                                    }
                                }


                                /*
                                 * =============================
                                 * INVALID COMMAND
                                 * =============================
                                 */

                                _ => {

                                    eprintln!();

                                    eprintln!(
                                        "SOC: Unknown command '{}'.",
                                        action
                                    );

                                    eprintln!(
                                        "Valid commands:"
                                    );

                                    eprintln!(
                                        "approve | reject | monitor | false-positive"
                                    );
                                }
                            }


                            /*
                             * =================================
                             * CLEAR PROCESSED SOC COMMAND
                             * =================================
                             */

                            let _ =

                                tokio::fs::write(

                                    SOC_COMMAND_FILE,

                                    "",

                                )

                                .await;


                            dashboard.display();

                        } else {

                            eprintln!();

                            eprintln!(
                                "SOC: Invalid command format."
                            );

                            eprintln!(
                                "Example: approve INC-0001"
                            );


                            /*
                             * Clear invalid command.
                             */

                            let _ =

                                tokio::fs::write(

                                    SOC_COMMAND_FILE,

                                    "",

                                )

                                .await;
                        }
                    }
                }
            }


            /*
             * =================================================
             * DASHBOARD + ML WINDOW REFRESH
             * =================================================
             *
             * Every 2 seconds:
             *
             * 1. Check whether any 30-second ML windows expired.
             * 2. Write completed feature windows to CSV.
             * 3. Refresh the single live dashboard.
             */

            _ = dashboard_timer.tick() => {

                /*
                 * Save completed ML feature windows.
                 */

                ml_collector.flush_expired();


                /*
                 * Refresh dashboard.
                 */

                dashboard.display();
            }


            /*
             * =================================================
             * CTRL+C
             * =================================================
             */

            _ = signal::ctrl_c() => {

                break;
            }
        }
    }


    /*
     * ========================================================
     * SAVE FINAL ML WINDOWS
     * ========================================================
     *
     * A device may have a partial window when Ctrl+C occurs.
     *
     * Save those remaining features before shutdown.
     */

    ml_collector.flush_all();


    /*
     * ========================================================
     * STOP BTMON
     * ========================================================
     */

    let _ =
        child.kill().await;


    /*
     * Wait for btmon cleanup.
     */

    let _ =
        child.wait().await;


    /*
     * ========================================================
     * FINAL SESSION SUMMARY
     * ========================================================
     */

    println!();

    stats.print_summary();


    Ok(())
}