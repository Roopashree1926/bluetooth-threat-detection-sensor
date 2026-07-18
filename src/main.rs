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

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use event_queue::EventQueue;

#[tokio::main]
async fn main() -> Result<()> {

    println!("Bluetooth Sensor Started");

    let detector = detector::PatternDetector::new();

    let mut queue = EventQueue::new(100);

    let mut stats = statistics::Statistics::new();

    let mut dashboard = dashboard::Dashboard::new();

    let mut child = Command::new("sudo")
        .arg("btmon")
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().unwrap();

    let mut reader = BufReader::new(stdout).lines();

    while let Some(line) = reader.next_line().await? {

        if let Some(event) = parser::parse_line(&line) {

            dashboard.update(&event);

            // Push current event into queue
            queue.push(event.clone());

            // Run detector
            detector.process(queue.recent());

            // Dashboard statistics
            match event.event_type {

                models::EventType::AdvertisingReport => {

                    stats.record("Advertising Flood");

                    let advertising = queue
                        .recent()
                        .iter()
                        .filter(|e| e.event_type == models::EventType::AdvertisingReport)
                        .count();

                    // Lower threshold for demo
                    if advertising >= 3 {
                        dashboard.threat("Advertising Flood");
                    }
                }

                models::EventType::AuthenticationFailed => {

                    stats.record("Authentication Failure");

                    let failed = queue
                        .recent()
                        .iter()
                        .filter(|e| e.event_type == models::EventType::AuthenticationFailed)
                        .count();

                    if failed >= 2 {
                        dashboard.threat("Authentication Failure");
                    }
                }

                models::EventType::PairingRequest => {

                    stats.record("Pairing Request Flood");

                    let pairing = queue
                        .recent()
                        .iter()
                        .filter(|e| e.event_type == models::EventType::PairingRequest)
                        .count();

                    if pairing >= 2 {
                        dashboard.threat("Pairing Request Flood");
                    }
                }

                models::EventType::DeviceFound => {

                    stats.record("Device Discovery");

                    let devices = queue
                        .recent()
                        .iter()
                        .filter(|e| e.event_type == models::EventType::DeviceFound)
                        .count();

                    if devices >= 5 {
                        dashboard.threat("Device Discovery Flood");
                    }
                }

                _ => {}
            }

            dashboard.display();
        }
    }

    stats.print_summary();

    Ok(())
}