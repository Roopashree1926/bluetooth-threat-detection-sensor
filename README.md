# Bluetooth Threat Detection Sensor

## Overview

The Bluetooth Threat Detection Sensor is a real-time Bluetooth Intrusion Detection System (IDS) developed in Rust. The application continuously monitors Bluetooth traffic using Linux's **btmon** utility, analyzes HCI events, detects suspicious Bluetooth activities, logs detected threats, generates reports, and displays a live monitoring dashboard.

The project is designed to demonstrate how Bluetooth communication can be monitored to identify potential security threats such as advertising floods, repeated authentication failures, device discovery floods, and pairing attacks.

---

# Objectives

- Monitor Bluetooth HCI packets in real time.
- Parse Bluetooth events from btmon.
- Detect suspicious Bluetooth attack patterns.
- Display live monitoring statistics.
- Store detected threats in CSV and JSON formats.
- Generate reports for forensic analysis.

---

# Features

- Real-time Bluetooth packet monitoring
- Live dashboard
- Bluetooth packet parser
- Packet builder
- Event queue management
- Advertising Flood detection
- Authentication Failure detection
- Device Discovery Flood detection
- Pairing Request Flood detection
- CSV logging
- JSON logging
- Threat report generation
- Session statistics
- Colorized terminal dashboard

---

# Technologies Used

- Rust
- Tokio
- btmon
- Regex
- Chrono
- Colored
- CSV
- JSON

---

# Project Structure

```
sensor/

├── Cargo.toml
├── src/
│
├── main.rs
├── parser/
├── detector/
├── dashboard/
├── logger/
├── json_logger/
├── reports/
├── statistics/
├── models/
├── event_queue/
├── signatures/
└── patterns/
```

---

# Working

1. The sensor launches btmon.
2. Bluetooth packets are captured.
3. Packet Builder combines packet lines.
4. Parser extracts Bluetooth events.
5. Events are stored inside an Event Queue.
6. Pattern Detector analyzes recent events.
7. Suspicious activities are detected.
8. Dashboard updates in real time.
9. Threats are logged into CSV and JSON files.
10. Reports are generated.

---

# Threats Detected

- Advertising Flood
- Authentication Failure
- Device Discovery Flood
- Pairing Request Flood
- Rapid Bluetooth Activity
- RSSI Anomaly (Framework)

---

# Dashboard

The dashboard displays:

- Packets Captured
- Advertising Reports
- Devices Found
- Connections
- Disconnections
- Authentication Failures
- Pairing Requests
- RSSI Updates
- Threat Count
- Latest Threat
- Monitoring Time

---

# Output Files

The application generates:

- threats.csv
- threats.json
- reports.txt

---

# Requirements

- Kali Linux
- Rust
- Cargo
- Bluetooth Adapter
- btmon

---

# Build

```
cargo build
```

---

# Run

```
cargo run
```

---

# Sample Dashboard

```
============================================================
        BLUETOOTH THREAT DETECTION SENSOR
============================================================
System Status : RUNNING

Packets Captured : 125

Advertising Reports : 48

Devices Found : 20

Threats Detected : 3

Latest Threat : Advertising Flood
============================================================
```

---

# Future Enhancements

- Web Dashboard
- Machine Learning based anomaly detection
- Email Alerts
- Mobile Notifications
- Database Integration
- Cloud Monitoring
- SIEM Integration

---

# Author

Project Developed using Rust for Bluetooth Security Monitoring and Threat Detection.