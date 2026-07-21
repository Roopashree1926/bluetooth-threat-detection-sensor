use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub enum IncidentStatus {
    PendingSocReview,
    Approved,
    Rejected,
    Monitoring,
    FalsePositive,
}

#[derive(Debug, Clone)]
pub struct SecurityIncident {
    pub id: String,

    pub created_at: DateTime<Utc>,

    pub threat_name: String,

    pub severity: String,

    pub device_mac: Option<String>,

    pub details: String,

    pub status: IncidentStatus,
}