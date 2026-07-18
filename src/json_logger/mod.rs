use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;

use chrono::Utc;
use serde_json::json;

pub fn log_json(threat: &str, severity: &str, details: &str) {

    create_dir_all("logs").unwrap();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/threats.json")
        .unwrap();

    let obj = json!({
        "timestamp": Utc::now().to_rfc3339(),
        "threat": threat,
        "severity": severity,
        "details": details
    });

    writeln!(file, "{}", obj).unwrap();
}