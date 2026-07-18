use crate::models::EventType;

#[derive(Debug)]
pub struct Signature {
    pub name: &'static str,
    pub sequence: Vec<EventType>,
    pub severity: &'static str,
}

pub fn load_signatures() -> Vec<Signature> {

    vec![

        Signature {

            name: "Advertising Flood",

            sequence: vec![
                EventType::AdvertisingReport,
                EventType::AdvertisingReport,
                EventType::AdvertisingReport,
            ],

            severity: "Medium",

        },

        Signature {

            name: "Authentication Failure",

            sequence: vec![
                EventType::ConnectionComplete,
                EventType::AuthenticationFailed,
                EventType::AuthenticationFailed,
                EventType::AuthenticationFailed,
            ],

            severity: "High",

        },

    ]

}