use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;

pub fn log_threat(name: &str, severity: &str) {

    println!("LOGGER CALLED");

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("threats.csv")
        .unwrap();

    writeln!(
        file,
        "{},{},{}",
        Utc::now().to_rfc3339(),
        name,
        severity
    ).unwrap();

    println!("CSV WRITTEN");
}