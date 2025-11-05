#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use iggy_common::get_stats::GetStats;
    use iggy_common::login_user::LoginUser;
    use iggy_common::ping::Ping;
    use serde_json::Value;
    use server::binary::command::ServerCommand;
    use std::fs;
    use std::process::{Command as ProcessCommand, Stdio};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    fn create_packet_from_server_command(command: &ServerCommand) -> Vec<u8> {
        let command_bytes = command.to_bytes();
        let length = command_bytes.len() as u32;
        let mut bytes = BytesMut::with_capacity(4 + command_bytes.len());
        bytes.put_u32_le(length);
        bytes.put_slice(&command_bytes);
        bytes.to_vec()
    }

    struct TsharkCapture {
        pcap_file: String,
    }

    impl TsharkCapture {
        fn new(port: u16) -> anyhow::Result<Self> {
            let pcap_file = format!("/tmp/iggy_test_{}.pcap", port);
            Ok(Self { pcap_file })
        }

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

        fn analyze(&self) -> anyhow::Result<Vec<Value>> {
            let dissector_path = std::env::current_dir()?
                .join("iggy_dissector.lua")
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

            for (i, packet) in packets.iter().enumerate() {
                println!(
                    "Packet {}: has iggy = {}",
                    i,
                    packet["_source"]["layers"].get("iggy").is_some()
                );
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

        let msg_type = iggy_layer["iggy.message_type"]
            .as_str()
            .expect("Failed to get message type");
        assert_eq!(msg_type, "Request", "Message type should be 'Request'");

        let length = iggy_layer["iggy.request.length"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .expect("Failed to parse LENGTH field");
        assert_eq!(length, 4, "LENGTH field should be 4 for PING");

        let code = iggy_layer["iggy.request.code"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .expect("Failed to parse CODE field");
        assert_eq!(code, 1, "CODE field should be 1 for PING");

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

        let code = iggy_layer["iggy.request.code"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .expect("Failed to parse CODE field");
        assert_eq!(code, 10, "CODE field should be 10 for GET_STATS");

        let command_name = iggy_layer["iggy.request.code_name"]
            .as_str()
            .expect("Failed to get command name");
        assert_eq!(command_name, "GetStats", "Command name should be 'GetStats'");

        println!("✓ GET_STATS dissection verified successfully!");
    }

    #[tokio::test]
    #[ignore]
    async fn test_login_user_dissection_with_tshark() {
        let port = 8093;
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

        let login_command = ServerCommand::LoginUser(LoginUser {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            version: Some("1.0.0".to_string()),
            context: Some("test".to_string()),
        });
        let login_packet = create_packet_from_server_command(&login_command);

        println!("Sending LOGIN_USER via ServerCommand: {} bytes", login_packet.len());

        stream
            .write_all(&login_packet)
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

        let code = iggy_layer["iggy.request.code"]
            .as_str()
            .and_then(|s| s.parse::<u32>().ok())
            .expect("Failed to parse CODE field");
        assert_eq!(code, 38, "CODE field should be 38 for LOGIN_USER");

        let command_name = iggy_layer["iggy.request.code_name"]
            .as_str()
            .expect("Failed to get command name");
        assert_eq!(command_name, "LoginUser", "Command name should be 'LoginUser'");

        let username = iggy_layer["iggy.login.username"]
            .as_str()
            .expect("Failed to get username");
        assert_eq!(username, "testuser", "Username should be 'testuser'");

        println!("✓ LOGIN_USER dissection verified successfully!");
    }
}
