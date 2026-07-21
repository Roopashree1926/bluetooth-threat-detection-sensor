use anyhow::Result;
use csv::ReaderBuilder;

#[derive(Debug, Clone)]
pub struct TrainingData {

    pub features: Vec<Vec<f64>>,

    pub labels: Vec<u32>,
}

pub struct DatasetLoader;

impl DatasetLoader {

    pub fn load_dataset(
        path: &str,
    ) -> Result<TrainingData> {

        let mut reader =
            ReaderBuilder::new()
                .has_headers(true)
                .from_path(path)?;

        let mut features =
            Vec::<Vec<f64>>::new();

        let mut labels =
            Vec::<u32>::new();

        for row in reader.records() {

            let record = row?;

            let sample = vec![

                record[2].parse::<f64>().unwrap_or(0.0),   // connections

                record[3].parse::<f64>().unwrap_or(0.0),   // disconnections

                record[4].parse::<f64>().unwrap_or(0.0),   // connection failures

                record[5].parse::<f64>().unwrap_or(0.0),   // authentication failures

                record[6].parse::<f64>().unwrap_or(0.0),   // pairing requests

                record[7].parse::<f64>().unwrap_or(0.0),   // advertising reports

                record[8].parse::<f64>().unwrap_or(0.0),   // rssi updates

                record[10].parse::<f64>().unwrap_or(0.0),  // average rssi

                record[11].parse::<f64>().unwrap_or(0.0),  // rssi range

                record[13].parse::<f64>().unwrap_or(0.0),  // total events

                record[14].parse::<f64>().unwrap_or(0.0),  // connection ratio
            ];

            features.push(sample);

 let label = if record.get(15).unwrap_or("").trim() == "ATTACK" {
    1
} else {
    0
};

            labels.push(label);
        }

        Ok(

            TrainingData {

                features,

                labels,
            }
        )
    }
}