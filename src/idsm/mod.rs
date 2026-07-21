use anyhow::Result;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;



#[derive(Serialize)]
struct IncomingSensorEvent {
    event_id: u32,
    source: String,
    description: String,
    context_data: Option<Vec<u8>>,
}

pub async fn send_to_idsm(
    idsm_ip: &str,
    idsm_port: &str,
    event_id: u32,
    description: &str,
    device_mac: &str,
) -> Result<()> {

    let payload = IncomingSensorEvent {
        event_id,
        source: "BLUETOOTH_SENSOR".to_string(),
        description: description.to_string(),
        context_data: Some(device_mac.as_bytes().to_vec()),
    };

    let json = serde_json::to_string(&payload)? + "\n";

    let addr = format!("{}:{}", idsm_ip, idsm_port);

    println!("Connecting to IDSM at {}", addr);

    let mut stream = TcpStream::connect(&addr).await?;

    stream.write_all(json.as_bytes()).await?;

    println!("Event sent to IDSM via raw TCP.");

    Ok(())
}