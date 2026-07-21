#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub name: String,
    pub severity: String,
    pub mac: Option<String>,
    pub details: String,
}