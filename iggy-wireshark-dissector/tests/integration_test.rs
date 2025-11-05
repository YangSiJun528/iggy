use bytes::{BufMut, BytesMut};
use iggy_common::get_stats::GetStats;
use iggy_common::ping::Ping;
use serde_json::Value;
use server::binary::command::ServerCommand;
use std::fs;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// Create a complete network packet from ServerCommand
/// Format: [LENGTH (4 bytes)][CODE + PAYLOAD from ServerCommand::to_bytes()]
///
/// This uses the actual ServerCommand enum which properly serializes commands
/// using the same logic as the real Iggy server.
fn create_packet_from_server_command(command: &ServerCommand) -> Vec<u8> {
    // ServerCommand::to_bytes() returns [CODE (4 bytes)][PAYLOAD (N bytes)]
    let command_bytes = command.to_bytes();

    // LENGTH = size of (CODE + PAYLOAD)
    let length = command_bytes.len() as u32;

    // Build complete packet: [LENGTH (4 bytes)][CODE + PAYLOAD]
    let mut bytes = BytesMut::with_capacity(4 + command_bytes.len());
    bytes.put_u32_le(length);
    bytes.put_slice(&command_bytes);

    bytes.to_vec()
}

/// Capture and analyze packets using tshark
struct TsharkCapture {
    pcap_file: String,
}

impl TsharkCapture {
    fn new(port: u16) -> anyhow::Result<Self> {
        let pcap_file = format!("/tmp/iggy_test_{}.pcap", port);
        Ok(Self { pcap_file })
    }

    /// Start tshark to capture packets to a file
    fn start_capture(&self, port: u16) -> anyhow::Result<std::process::Child> {
        let process = ProcessCommand::new("tshark")
            .args([
                "-i",
                "lo0",
                "-w",
                &self.pcap_file,
                "-f",
                &format!("tcp port {}", port),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(process)
    }

    /// Analyze captured packets with Lua dissector
    fn analyze(&self) -> anyhow::Result<Vec<Value>> {
        let dissector_path = std::env::current_dir()?
            .join("iggy_simple.lua")
            .to_string_lossy()
            .to_string();

        let output = ProcessCommand::new("tshark")
            .args([
                "-r",
                &self.pcap_file,
                "-Y",
                "iggy",
                "-T",
                "json",
                "-X",
                &format!("lua_script:{}", dissector_path),
            ])
            .output()?;

        // Always print stderr to see Lua errors
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("=== tshark stderr ===");
            eprintln!("{}", stderr);
            eprintln!("=== end stderr ===");
        }

        if !output.status.success() {
            return Err(anyhow::anyhow!("tshark failed: {}", stderr));
        }

        let json_str = String::from_utf8(output.stdout)?;

        let packets: Vec<Value> = serde_json::from_str(&json_str)?;

        // Debug: print iggy layer structure
        for (i, packet) in packets.iter().enumerate() {
            println!("Packet {}: has iggy = {}", i, packet["_source"]["layers"].get("iggy").is_some());
            if let Some(iggy) = packet["_source"]["layers"].get("iggy") {
                println!("Iggy layer: {}", serde_json::to_string_pretty(iggy).unwrap());
            }
        }

        Ok(packets)
    }
}

impl Drop for TsharkCapture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.pcap_file);
    }
}

/// Simple TCP server that accepts connections and discards data
async fn run_dummy_server(port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            loop {
                match socket.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(_n) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

#[tokio::test]
#[ignore]
async fn test_ping_dissection_with_tshark() {
    let port = 8091;

    let capture = TsharkCapture::new(port).expect("Failed to create capture");
    let mut tshark = capture.start_capture(port).expect("Failed to start tshark");

    sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        let _ = run_dummy_server(port).await;
    });
    sleep(Duration::from_millis(500)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let ping_command = ServerCommand::Ping(Ping::default());
    let ping_packet = create_packet_from_server_command(&ping_command);

    println!("Sending PING via ServerCommand: {} bytes", ping_packet.len());
    println!("  Hex: {}", hex::encode(&ping_packet));

    stream
        .write_all(&ping_packet)
        .await
        .expect("Failed to send packet");
    stream.flush().await.expect("Failed to flush");

    sleep(Duration::from_secs(1)).await;

    let _ = tshark.kill();
    sleep(Duration::from_millis(500)).await;

    let packets = capture.analyze().expect("Failed to analyze packets");

    assert!(!packets.is_empty(), "No packets captured");

    let iggy_packet = packets
        .iter()
        .find(|p| p["_source"]["layers"].get("iggy").is_some())
        .expect("No Iggy packet found");

    let layers = &iggy_packet["_source"]["layers"];
    let iggy_layer = &layers["iggy"];

    // Verify message type is Request
    let msg_type = iggy_layer["iggy.message_type"]
        .as_str()
        .expect("Failed to get message type");
    assert_eq!(msg_type, "Request", "Message type should be 'Request'");

    // Verify LENGTH field (request.length)
    let length = iggy_layer["iggy.request.length"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse LENGTH field");
    assert_eq!(length, 4, "LENGTH field should be 4 for PING");

    // Verify CODE field (request.code)
    let code = iggy_layer["iggy.request.code"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse CODE field");
    assert_eq!(code, 1, "CODE field should be 1 for PING");

    // Verify command name (request.code_name)
    let command_name = iggy_layer["iggy.request.code_name"]
        .as_str()
        .expect("Failed to get command name");
    assert_eq!(command_name, "Ping", "Command name should be 'Ping'");

    println!("✓ PING dissection verified successfully!");
}

#[tokio::test]
#[ignore]
async fn test_get_stats_dissection_with_tshark() {
    let port = 8092;

    let capture = TsharkCapture::new(port).expect("Failed to create capture");
    let mut tshark = capture.start_capture(port).expect("Failed to start tshark");

    sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        let _ = run_dummy_server(port).await;
    });
    sleep(Duration::from_millis(500)).await;

    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    let stats_command = ServerCommand::GetStats(GetStats::default());
    let stats_packet = create_packet_from_server_command(&stats_command);

    println!("Sending GET_STATS via ServerCommand: {} bytes", stats_packet.len());
    println!("  Hex: {}", hex::encode(&stats_packet));

    stream
        .write_all(&stats_packet)
        .await
        .expect("Failed to send packet");
    stream.flush().await.expect("Failed to flush");

    sleep(Duration::from_secs(1)).await;

    let _ = tshark.kill();
    sleep(Duration::from_millis(500)).await;

    let packets = capture.analyze().expect("Failed to analyze packets");

    assert!(!packets.is_empty(), "No packets captured");

    let iggy_packet = packets
        .iter()
        .find(|p| p["_source"]["layers"].get("iggy").is_some())
        .expect("No Iggy packet found");

    let layers = &iggy_packet["_source"]["layers"];
    let iggy_layer = &layers["iggy"];

    let msg_type = iggy_layer["iggy.message_type"]
        .as_str()
        .expect("Failed to get message type");
    assert_eq!(msg_type, "Request", "Message type should be 'Request'");

    let length = iggy_layer["iggy.request.length"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse LENGTH field");
    assert_eq!(length, 4, "LENGTH field should be 4 for GET_STATS");

    let code = iggy_layer["iggy.request.code"]
        .as_str()
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse CODE field");
    assert_eq!(code, 10, "CODE field should be 10 for GET_STATS");

    let command_name = iggy_layer["iggy.request.code_name"]
        .as_str()
        .expect("Failed to get command name");
    assert_eq!(
        command_name, "GetStats",
        "Command name should be 'GetStats'"
    );

    println!("✓ GET_STATS dissection verified successfully!");
}
