use anyhow::Result;
use csv::{ReaderBuilder, WriterBuilder};

pub struct DatasetLabeler;

impl DatasetLabeler {
    pub fn label_dataset(
        input_file: &str,
        output_file: &str,
    ) -> Result<()> {

        let mut reader =
            ReaderBuilder::new()
                .has_headers(true)
                .from_path(input_file)?;

        let headers =
            reader.headers()?.clone();

        let mut writer =
            WriterBuilder::new()
                .from_path(output_file)?;

        writer.write_record(&headers)?;

        let mut attack_count = 0;
        let mut normal_count = 0;

        for result in reader.records() {

            let record = result?;

            let connections: u32 =
                record[2].parse().unwrap_or(0);

            let disconnections: u32 =
                record[3].parse().unwrap_or(0);

            let advertising_reports: u32 =
                record[7].parse().unwrap_or(0);

            let label =
                if advertising_reports >= 10 {

                    attack_count += 1;

                    "ATTACK"

                } else if connections >= 5
                    && disconnections >= 5 {

                    attack_count += 1;

                    "ATTACK"

                } else {

                    normal_count += 1;

                    "NORMAL"
                };

            let mut row: Vec<String> =
                record.iter()
                    .map(|s| s.to_string())
                    .collect();

            row.pop();

            row.push(label.to_string());

            writer.write_record(&row)?;
        }

        writer.flush()?;

        println!();
        println!("========================================");
        println!("Dataset Labeling Completed");
        println!("========================================");
        println!("ATTACK Rows : {}", attack_count);
        println!("NORMAL Rows : {}", normal_count);
        println!("Output File : {}", output_file);
        println!("========================================");

        Ok(())
    }
}