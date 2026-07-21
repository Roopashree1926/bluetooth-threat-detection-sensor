mod ml;

use anyhow::Result;
use ml::labeler::DatasetLabeler;

fn main() -> Result<()> {

    println!("========================================");
    println!(" Bluetooth ML Dataset Labeler");
    println!("========================================");

    DatasetLabeler::label_dataset(
        "bluetooth_ml_dataset.csv",
        "bluetooth_ml_dataset_labeled.csv",
    )?;

    println!();
    println!("Dataset labeling completed successfully.");

    Ok(())
}
