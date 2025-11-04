use bytes::{BufMut, BytesMut};
use iggy_common::get_stats::GetStats;
use iggy_common::ping::Ping;
use serde_json::Value;
use server::binary::command::ServerCommand;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command as ProcessCommand, Stdio};
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

struct TsharkCapture {
    process: Child,
}

impl TsharkCapture {
    /// Start tshark in live capture mode
    fn start(port: u16) -> anyhow::Result<Self> {
        let dissector_path = std::env::current_dir()?
            .join("iggy_simple.lua")
            .to_string_lossy()
            .to_string();

        let process = ProcessCommand::new("tshark")
            .args([
                "-i",
                "lo0", // macOS loopback interface
                "-f",
                &format!("tcp port {}", port),
                "-Y",
                "iggy",
                "-T",
                "json",
                "-l", // line buffered
                "-X",
                &format!("lua_script:{}", dissector_path),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(Self { process })
    }

    /// Read next packet dissection result
    fn read_next_packet(&mut self, timeout: Duration) -> anyhow::Result<Option<Value>> {
        let stdout = self
            .process
            .stdout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No stdout"))?;

        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        // Simple timeout implementation
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if reader.read_line(&mut line)? > 0 {
                if line.trim().is_empty() {
                    line.clear();
                    continue;
                }

                let packet: Value = serde_json::from_str(&line)?;
                return Ok(Some(packet));
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        Ok(None)
    }
}

impl Drop for TsharkCapture {
    fn drop(&mut self) {
        let _ = self.process.kill();
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
                    Ok(0) => break, // Connection closed
                    Ok(_n) => {
                        // Just discard the data
                    }
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
#[ignore] // Requires tshark to be installed
async fn test_ping_dissection_with_tshark() {
    let port = 8091; // Use different port to avoid conflicts

    // 1. Start tshark
    let mut tshark = TsharkCapture::start(port).expect("Failed to start tshark");
    sleep(Duration::from_secs(1)).await; // Wait for tshark to initialize

    // 2. Start dummy server
    tokio::spawn(async move {
        let _ = run_dummy_server(port).await;
    });
    sleep(Duration::from_millis(500)).await;

    // 3. Connect and send PING packet
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    // Use ServerCommand enum - this uses the actual server's serialization logic
    let ping_command = ServerCommand::Ping(Ping::default());
    let ping_packet = create_packet_from_server_command(&ping_command);

    println!("Sending PING via ServerCommand: {} bytes", ping_packet.len());

    stream
        .write_all(&ping_packet)
        .await
        .expect("Failed to send packet");
    stream.flush().await.expect("Failed to flush");

    // Give tshark some time to process
    sleep(Duration::from_secs(1)).await;

    // 4. Read dissection result
    let result = tshark
        .read_next_packet(Duration::from_secs(5))
        .expect("Failed to read tshark output");

    assert!(result.is_some(), "No packet captured by tshark");

    let packet = result.unwrap();
    let layers = &packet["_source"]["layers"];

    // 5. Verify dissection results
    // Check that iggy protocol was detected
    assert!(
        layers.get("iggy").is_some(),
        "Iggy protocol layer not found"
    );

    // Verify LENGTH field
    let length = layers["iggy"]["iggy.length"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse LENGTH field");
    assert_eq!(length, 4, "LENGTH field should be 4 for PING");

    // Verify CODE field
    let code = layers["iggy"]["iggy.code"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse CODE field");
    assert_eq!(code, 1, "CODE field should be 1 for PING");

    // Verify command name
    let command_name = layers["iggy"]["iggy.code_name"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .expect("Failed to get command name");
    assert_eq!(command_name, "Ping", "Command name should be 'Ping'");

    println!("✓ PING dissection verified successfully!");
}

#[tokio::test]
#[ignore] // Requires tshark to be installed
async fn test_get_stats_dissection_with_tshark() {
    let port = 8092; // Use different port

    // 1. Start tshark
    let mut tshark = TsharkCapture::start(port).expect("Failed to start tshark");
    sleep(Duration::from_secs(1)).await;

    // 2. Start dummy server
    tokio::spawn(async move {
        let _ = run_dummy_server(port).await;
    });
    sleep(Duration::from_millis(500)).await;

    // 3. Connect and send GET_STATS packet
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to connect");

    // Use ServerCommand enum - this uses the actual server's serialization logic
    let stats_command = ServerCommand::GetStats(GetStats::default());
    let stats_packet = create_packet_from_server_command(&stats_command);

    println!("Sending GET_STATS via ServerCommand: {} bytes", stats_packet.len());

    stream
        .write_all(&stats_packet)
        .await
        .expect("Failed to send packet");
    stream.flush().await.expect("Failed to flush");

    sleep(Duration::from_secs(1)).await;

    // 4. Read dissection result
    let result = tshark
        .read_next_packet(Duration::from_secs(5))
        .expect("Failed to read tshark output");

    assert!(result.is_some(), "No packet captured by tshark");

    let packet = result.unwrap();
    let layers = &packet["_source"]["layers"];

    // 5. Verify dissection results
    assert!(
        layers.get("iggy").is_some(),
        "Iggy protocol layer not found"
    );

    let length = layers["iggy"]["iggy.length"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse LENGTH field");
    assert_eq!(length, 4, "LENGTH field should be 4 for GET_STATS");

    let code = layers["iggy"]["iggy.code"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .expect("Failed to parse CODE field");
    assert_eq!(code, 10, "CODE field should be 10 for GET_STATS");

    let command_name = layers["iggy"]["iggy.code_name"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .expect("Failed to get command name");
    assert_eq!(
        command_name, "GetStats",
        "Command name should be 'GetStats'"
    );

    println!("✓ GET_STATS dissection verified successfully!");
}
