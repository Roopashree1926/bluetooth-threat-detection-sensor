use anyhow::Result;

use smartcore::linalg::basic::matrix::DenseMatrix;

use smartcore::tree::decision_tree_classifier::{
    DecisionTreeClassifier,
    DecisionTreeClassifierParameters,
};

use crate::ml::dataset::DatasetLoader;

pub struct ModelTrainer;

impl ModelTrainer {

    pub fn train() -> Result<()> {

        println!("======================================");
        println!(" Bluetooth ML Model Training");
        println!("======================================");

        let dataset =
            DatasetLoader::load_dataset(
                "bluetooth_ml_dataset_labeled.csv"
            )?;

        println!("Samples Loaded : {}", dataset.features.len());

        let x =
            DenseMatrix::from_2d_vec(
                &dataset.features
            )?;

        let y =
            dataset.labels;

        let model =
            DecisionTreeClassifier::fit(
                &x,
                &y,
                DecisionTreeClassifierParameters::default(),
            )?;

        let predictions =
            model.predict(&x)?;

        let mut correct = 0;

        for i in 0..y.len() {

            if predictions[i] == y[i] {

                correct += 1;
            }
        }

        let accuracy =
            (correct as f64 / y.len() as f64) * 100.0;

        println!();
        println!("Training Complete");
        println!("Accuracy : {:.2}%", accuracy);

        Ok(())
    }
}