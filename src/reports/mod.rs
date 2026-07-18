use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;

use chrono::Utc;

pub fn generate_report(
    threat: &str,
    severity: &str,
    details: &str,
) {

    create_dir_all("reports").unwrap();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("reports/threat_report.txt")
        .unwrap();

    writeln!(file, "======================================").unwrap();
    writeln!(file, "Bluetooth Threat Report").unwrap();
    writeln!(file, "Time      : {}", Utc::now()).unwrap();
    writeln!(file, "Threat    : {}", threat).unwrap();
    writeln!(file, "Severity  : {}", severity).unwrap();
    writeln!(file, "Details   : {}", details).unwrap();
    writeln!(file, "Recommendation: Investigate suspicious Bluetooth activity.").unwrap();
    writeln!(file, "======================================\n").unwrap();
}