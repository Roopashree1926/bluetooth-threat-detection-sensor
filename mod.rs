use std::collections::HashMap;

pub struct Statistics {
    counts: HashMap<String, usize>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn record(&mut self, threat: &str) {
        *self.counts.entry(threat.to_string()).or_insert(0) += 1;
    }

    pub fn print_summary(&self) {

        println!();
        println!("============================================================");
        println!("                 FINAL SESSION SUMMARY");
        println!("============================================================");

        let mut total = 0;

        for (name, count) in &self.counts {

            println!("{:<35} {}", name, count);

            total += count;

        }

        println!("------------------------------------------------------------");
        println!("Total Threats Detected              : {}", total);
        println!("CSV Log                            : Saved");
        println!("JSON Log                           : Saved");
        println!("Threat Report                      : Generated");
        println!("============================================================");
        println!(" Bluetooth Threat Detection Sensor Stopped");
        println!("============================================================");
        println!();

    }
}