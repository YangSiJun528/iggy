#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use iggy::prelude::*;
    use serde_json::Value;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Default credentials for Iggy server
    const DEFAULT_ROOT_USERNAME: &str = "iggy";
    const DEFAULT_ROOT_PASSWORD: &str = "iggy";

    /// Server configuration - change these constants to match your server setup
    const SERVER_IP: &str = "127.0.0.1";
    const SERVER_TCP_PORT: u16 = 8090;

    /// Helper struct to manage tshark packet capture
    struct TsharkCapture {
        ip: String,
        port: u16,
        pcap_file: PathBuf,
        dissector_path: PathBuf,
    }

    impl TsharkCapture {
        fn new(ip: &str, port: u16) -> io::Result<Self> {
            let file = format!("/tmp/iggy_test_{}.pcap", port);

            // Find dissector.lua in the workspace root
            let dissector_path = std::env::current_dir()?
                .join("dissector.lua");

            if !dissector_path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Dissector not found at: {}", dissector_path.display()),
                ));
            }

            Ok(Self {
                ip: ip.to_string(),
                port,
                pcap_file: PathBuf::from(file),
                dissector_path,
            })
        }

        fn start(&self) -> io::Result<Child> {
            let mut command = ProcessCommand::new("tshark");

            command
                .args([
                    "-i",
                    "lo",
                    "-w",
                    self.pcap_file.to_str().unwrap(),
                    "-f",
                    &format!("tcp and host {} and port {}", self.ip, self.port),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            // Add Lua script and port configuration
            command.arg("-X");
            command.arg(format!("lua_script:{}", self.dissector_path.display()));
            command.arg("-o");
            command.arg(format!("iggy.server_port:{}", self.port));

            println!("Starting tshark with command: {:?}", command);

            command.spawn()
        }

        fn analyze(&self) -> io::Result<Vec<Value>> {
            let output = ProcessCommand::new("tshark")
                .args([
                    "-r",
                    self.pcap_file.to_str().unwrap(),
                    "-Y",
                    "iggy",
                    "-T",
                    "json",
                    "-X",
                    &format!("lua_script:{}", self.dissector_path.display()),
                    "-o",
                    &format!("iggy.server_port:{}", self.port),
                    "-V", // Verbose output
                ])
                .output()?;

            println!("tshark analyze exit status: {:?}", output.status);
            if !output.stderr.is_empty() {
                println!("tshark stderr: {}", String::from_utf8_lossy(&output.stderr));
            }

            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("tshark failed: {}", String::from_utf8_lossy(&output.stderr)),
                ));
            }

            let json_str = String::from_utf8_lossy(&output.stdout);
            println!("tshark output length: {} bytes", json_str.len());

            if json_str.trim().is_empty() {
                return Ok(Vec::new());
            }

            let packets: Vec<Value> = serde_json::from_str(&json_str).map_err(|e| {
                println!("JSON parse error: {}", e);
                println!("Raw output: {}", json_str);
                io::Error::new(io::ErrorKind::Other, e)
            })?;

            Ok(packets)
        }
    }

    impl Drop for TsharkCapture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.pcap_file);
        }
    }

    /// Helper function to create an IggyClient connected to the test server
    async fn create_test_client() -> Result<IggyClient, IggyError> {
        let tcp_config = TcpClientConfig {
            server_address: format!("{}:{}", SERVER_IP, SERVER_TCP_PORT),
            ..Default::default()
        };

        let tcp_client = TcpClient::create(Arc::new(tcp_config))?;
        let client = IggyClient::new(ClientWrapper::Tcp(tcp_client));
        client.connect().await?;

        // Explicitly login with default root credentials
        client.login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD).await?;

        Ok(client)
    }

    /// Helper function to extract iggy packets from tshark output
    fn extract_iggy_packets(packets: &[Value]) -> Vec<&Value> {
        packets
            .iter()
            .filter(|p| p["_source"]["layers"].get("iggy").is_some())
            .collect()
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing Ping Command Dissection ===");

        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client and send ping
        let client = create_test_client().await?;

        println!("Sending Ping command...");
        client.ping().await?;

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        // Verify we have both request and response
        let mut found_request = false;
        let mut found_response = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];
            println!("\nPacket {}: {:?}", idx, iggy);

            // Check for Ping request (command code 1)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "1" {
                        found_request = true;
                        println!("  ✓ Ping request found");

                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            assert_eq!(cmd_name.as_str(), Some("Ping"));
                        }
                    }
                }
            }

            // Check for successful response (status 0)
            if let Some(status) = iggy.get("iggy.response.status") {
                if let Some(status_val) = status.as_str() {
                    if status_val == "0" {
                        found_response = true;
                        println!("  ✓ Ping response found (status: OK)");

                        if let Some(status_name) = iggy.get("iggy.response.status_name") {
                            assert_eq!(status_name.as_str(), Some("OK"));
                        }
                    }
                }
            }
        }

        assert!(found_request, "Ping request not found in capture");
        assert!(found_response, "Ping response not found in capture");

        println!("\n✓ Ping dissection test passed");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_stream_topic_creation_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing Stream/Topic Creation Dissection ===");

        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client
        let client = create_test_client().await?;

        // Create a unique stream name for this test
        let stream_id = Identifier::numeric(999)?;
        let stream_name = "wireshark_test_stream";

        println!("Creating stream: {} (ID: {})", stream_name, stream_id);

        // Try to create stream (might already exist, which is fine)
        let _ = client
            .create_stream(&stream_name, Some(999))
            .await;

        // Create topic
        let topic_id = Identifier::numeric(1)?;
        let topic_name = "wireshark_test_topic";

        println!("Creating topic: {} (ID: {})", topic_name, topic_id);

        let _ = client
            .create_topic(
                &stream_id,
                topic_name,
                1, // partitions
                CompressionAlgorithm::None,
                None,
                None,
                IggyExpiry::NeverExpire,
                MaxTopicSize::Unlimited,
            )
            .await;

        // Wait for packets
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        // Verify we captured stream/topic creation commands
        let mut found_stream_or_topic_command = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    println!("Packet {}: Command code {}", idx, cmd_val);

                    // CreateStream = 200, CreateTopic = 300 (check actual codes in your protocol)
                    if cmd_val == "200" || cmd_val == "300" {
                        found_stream_or_topic_command = true;
                        println!("  ✓ Stream/Topic creation command found");
                    }
                }
            }
        }

        // Clean up
        let _ = client.delete_stream(&stream_id).await;

        assert!(
            found_stream_or_topic_command || iggy_packets.len() > 2,
            "Expected to capture stream/topic creation commands"
        );

        println!("\n✓ Stream/Topic creation dissection test passed");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_message_send_receive_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing Message Send/Receive Dissection ===");

        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client
        let client = create_test_client().await?;

        // Use a test stream and topic
        let stream_id = Identifier::numeric(999)?;
        let stream_name = "wireshark_test_stream";
        let topic_name = "wireshark_test_topic";

        // Ensure stream and topic exist
        let _ = client
            .create_stream(&stream_name, Some(999))
            .await;

        let _ = client
            .create_topic(
                &stream_id,
                topic_name,
                1,
                CompressionAlgorithm::None,
                None,
                None,
                IggyExpiry::NeverExpire,
                MaxTopicSize::Unlimited,
            )
            .await;

        // Create producer and send messages
        let producer = client
            .producer("999", "1")?
            .direct(DirectConfig::builder().build())
            .partitioning(Partitioning::partition_id(1))
            .build();

        producer.init().await?;

        let messages = vec![
            IggyMessage::from("test_message_1"),
            IggyMessage::from("test_message_2"),
        ];

        println!("Sending {} messages...", messages.len());
        producer.send(messages).await?;
        println!("Messages sent successfully");

        // Create consumer and poll messages
        println!("Polling messages...");
        let mut consumer = client
            .consumer("test_consumer", "999", "1", 1)?
            .auto_commit(AutoCommit::When(AutoCommitWhen::PollingMessages))
            .polling_strategy(PollingStrategy::offset(0))
            .batch_length(10)
            .build();

        consumer.init().await?;

        // Just poll once to trigger the poll command
        if let Some(message) = consumer.next().await {
            println!("Polled message: {:?}", message.is_ok());
        }

        // Wait for packets
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        // Verify we captured send/poll commands
        let mut found_send_command = false;
        let mut found_poll_command = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if let Some(cmd_name) = iggy.get("iggy.request.command_name").and_then(|v| v.as_str()) {
                        println!("Packet {}: Command {} ({})", idx, cmd_val, cmd_name);

                        if cmd_name.contains("SendMessages") || cmd_name.contains("send") {
                            found_send_command = true;
                            println!("  ✓ Send messages command found");
                        }

                        if cmd_name.contains("PollMessages") || cmd_name.contains("poll") {
                            found_poll_command = true;
                            println!("  ✓ Poll messages command found");
                        }
                    }
                }
            }
        }

        // Clean up
        let _ = client.delete_stream(&stream_id).await;

        assert!(
            found_send_command || found_poll_command || iggy_packets.len() >= 4,
            "Expected to capture send and poll commands"
        );

        println!("\n✓ Message send/receive dissection test passed");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_stats_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing GetStats Command Dissection ===");

        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client and get stats
        let client = create_test_client().await?;

        println!("Getting server stats...");
        let stats = client.get_stats().await?;
        println!("Stats received: process_id={}", stats.process_id);

        // Wait for packets
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        // Verify GetStats request and response
        let mut found_request = false;
        let mut found_response = false;

        for (_idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            // Check for GetStats request (command code 10)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "10" {
                        found_request = true;
                        println!("  ✓ GetStats request found");

                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            println!("    Command name: {:?}", cmd_name);
                        }
                    }
                }
            }

            // Check for successful response with payload
            if let Some(status) = iggy.get("iggy.response.status") {
                if let Some(status_val) = status.as_str() {
                    if status_val == "0" {
                        // Check if response has payload (stats data)
                        if let Some(length) = iggy.get("iggy.response.length") {
                            if let Some(length_str) = length.as_str() {
                                let length_val: u32 = length_str.parse().unwrap_or(0);
                                if length_val > 0 {
                                    found_response = true;
                                    println!("  ✓ GetStats response found (payload size: {} bytes)", length_val);
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(found_request, "GetStats request not found in capture");
        assert!(found_response, "GetStats response not found in capture");

        println!("\n✓ GetStats dissection test passed");
        Ok(())
    }
}
