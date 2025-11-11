#[cfg(test)]
mod tests {
    use iggy::prelude::*;
    use serde_json::Value;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;
    use iggy::quic::quic_client::QuicClient;

    /// Default credentials for Iggy server
    const DEFAULT_ROOT_USERNAME: &str = "iggy";
    const DEFAULT_ROOT_PASSWORD: &str = "iggy";

    /// Server configuration - change these constants to match your server setup
    const SERVER_IP: &str = "127.0.0.1";
    const SERVER_TCP_PORT: u16 = 8090;
    const SERVER_QUIC_PORT: u16 = 8080;

    /// Helper struct to manage tshark packet capture
    struct TsharkCapture {
        ip: String,
        tcp_port: u16,
        quic_port: u16,
        pcap_file: PathBuf,
        dissector_path: PathBuf,
    }

    impl TsharkCapture {
        fn new(ip: &str) -> io::Result<Self> {
            let file = format!("/tmp/iggy_test.pcap");

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
                tcp_port: SERVER_TCP_PORT,
                quic_port: SERVER_QUIC_PORT,
                pcap_file: PathBuf::from(file),
                dissector_path,
            })
        }

        fn start(&self) -> io::Result<Child> {
            let mut command = ProcessCommand::new("tshark");

            // Capture both TCP and QUIC ports
            let filter = format!(
                "host {} and (tcp port {} or udp port {})",
                self.ip, self.tcp_port, self.quic_port
            );

            command
                .args([
                    "-i",
                    "lo",
                    "-w",
                    self.pcap_file.to_str().unwrap(),
                    "-f",
                    &filter,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            // Add Lua script and port configurations
            command.arg("-X");
            command.arg(format!("lua_script:{}", self.dissector_path.display()));
            command.arg("-o");
            command.arg(format!("iggy.tcp_port:{}", self.tcp_port));
            command.arg("-o");
            command.arg(format!("iggy.quic_port:{}", self.quic_port));

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
                    &format!("iggy.tcp_port:{}", self.tcp_port),
                    "-o",
                    &format!("iggy.quic_port:{}", self.quic_port),
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

    /// Helper function to create an IggyClient connected to the test server via TCP
    async fn create_test_tcp_client() -> Result<IggyClient, IggyError> {
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

    /// Helper function to create an IggyClient connected to the test server via QUIC
    async fn create_test_quic_client() -> Result<IggyClient, IggyError> {
        let quic_config = QuicClientConfig {
            server_address: format!("{}:{}", SERVER_IP, SERVER_QUIC_PORT),
            server_name: "localhost".to_string(),
            ..Default::default()
        };

        let quic_client = QuicClient::create(Arc::new(quic_config))?;
        let client = IggyClient::new(ClientWrapper::Quic(quic_client));
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

    /// Helper function to print packet details for debugging
    fn print_packet_json(packets: &[Value], show_all: bool) {
        println!("\n=== Captured Packets JSON ===");

        for (idx, packet) in packets.iter().enumerate() {
            println!("\n--- Packet {} ---", idx);

            if show_all {
                // Print full packet JSON
                println!("{}", serde_json::to_string_pretty(packet).unwrap_or_else(|_| "Error serializing packet".to_string()));
            } else {
                // Print only relevant layers: TCP and Iggy
                if let Some(layers) = packet["_source"]["layers"].as_object() {
                    // TCP layer
                    // if let Some(tcp) = layers.get("tcp") {
                    //     println!("TCP Layer:");
                    //     println!("{}", serde_json::to_string_pretty(tcp).unwrap_or_else(|_| "Error".to_string()));
                    // }

                    // Iggy layer
                    if let Some(iggy) = layers.get("iggy") {
                        println!("\nIggy Protocol Layer:");
                        println!("{}", serde_json::to_string_pretty(iggy).unwrap_or_else(|_| "Error".to_string()));
                    }
                }
            }
        }
        println!("\n=== End of Packets ===\n");
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing TCP Ping (Command 1) Dissection ===");

        // Start packet capture (captures both TCP and QUIC)
        let capture = TsharkCapture::new(SERVER_IP)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create TCP client (this will also send login, which is fine)
        let client = create_test_tcp_client().await?;

        println!("Sending Ping command...");
        client.ping().await?;

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        println!("Total packets captured: {}", packets.len());
        println!("Iggy packets found: {}", iggy_packets.len());

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify we have both Ping request and response
        let mut found_request = false;
        let mut found_response = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            // Check for Ping request (command code 1)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "1" {
                        found_request = true;
                        println!("Packet {}: ✓ Ping request found", idx);

                        // Verify command name
                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            assert_eq!(cmd_name.as_str(), Some("Ping"), "Command name should be 'Ping'");
                            println!("  - Command name: Ping");
                        }

                        // Verify request length (should be 4, only command code, no payload)
                        if let Some(length) = iggy.get("iggy.request.length") {
                            assert_eq!(length.as_str(), Some("4"), "Ping request length should be 4");
                            println!("  - Request length: 4");
                        }
                    }
                }
            }

            // Check for Ping response (status 0, no payload)
            if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                if cmd_name.as_str() == Some("Ping") {
                    if let Some(status) = iggy.get("iggy.response.status") {
                        if let Some(status_val) = status.as_str() {
                            if status_val == "0" {
                                // Check response length (should be 0 for Ping)
                                if let Some(length) = iggy.get("iggy.response.length") {
                                    if length.as_str() == Some("0") {
                                        found_response = true;
                                        println!("Packet {}: ✓ Ping response found", idx);
                                        println!("  - Status: OK (0)");
                                        println!("  - Response length: 0");

                                        // Verify status name
                                        if let Some(status_name) = iggy.get("iggy.response.status_name") {
                                            assert_eq!(status_name.as_str(), Some("OK"), "Status name should be 'OK'");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(found_request, "Ping request (command 1) not found in capture");
        assert!(found_response, "Ping response (status 0, length 0) not found in capture");

        println!("\n✓ Ping dissection test passed - verified request and response");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_login_user_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing TCP LoginUser (Command 38) Dissection ===");

        // Start packet capture (captures both TCP and QUIC)
        let capture = TsharkCapture::new(SERVER_IP)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create TCP client without auto-login, then manually login
        let tcp_config = TcpClientConfig {
            server_address: format!("{}:{}", SERVER_IP, SERVER_TCP_PORT),
            ..Default::default()
        };

        let tcp_client = TcpClient::create(Arc::new(tcp_config))?;
        let client = IggyClient::new(ClientWrapper::Tcp(tcp_client));
        client.connect().await?;

        println!("Sending LoginUser command...");
        client.login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD).await?;
        println!("Login successful");

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        println!("Total packets captured: {}", packets.len());
        println!("Iggy packets found: {}", iggy_packets.len());

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify we have both LoginUser request and response
        let mut found_request = false;
        let mut found_response = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            // Check for LoginUser request (command code 38)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "38" {
                        found_request = true;
                        println!("Packet {}: ✓ LoginUser request found", idx);

                        // Verify command name
                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            assert_eq!(cmd_name.as_str(), Some("LoginUser"), "Command name should be 'LoginUser'");
                            println!("  - Command name: LoginUser");
                        }

                        // Verify username field
                        if let Some(username) = iggy.get("iggy.login_user.req.username") {
                            assert_eq!(username.as_str(), Some(DEFAULT_ROOT_USERNAME), "Username should match");
                            println!("  - Username: {}", DEFAULT_ROOT_USERNAME);
                        }

                        // Verify request has username length field
                        if let Some(username_len) = iggy.get("iggy.login_user.req.username_len") {
                            println!("  - Username length: {}", username_len.as_str().unwrap_or("N/A"));
                        }

                        // Verify request has password length field
                        if let Some(password_len) = iggy.get("iggy.login_user.req.password_len") {
                            println!("  - Password length: {}", password_len.as_str().unwrap_or("N/A"));
                        }
                    }
                }
            }

            // Check for LoginUser response (status 0 with user_id payload)
            if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                if cmd_name.as_str() == Some("LoginUser") {
                    if let Some(status) = iggy.get("iggy.response.status") {
                        if let Some(status_val) = status.as_str() {
                            if status_val == "0" {
                                // Check if response has payload_tree with user_id field
                                if let Some(payload_tree) = iggy.get("iggy.response.payload_tree") {
                                    if let Some(user_id) = payload_tree.get("iggy.login_user.resp.user_id") {
                                        found_response = true;
                                        println!("Packet {}: ✓ LoginUser response found", idx);
                                        println!("  - Status: OK (0)");
                                        println!("  - User ID: {}", user_id.as_str().unwrap_or("N/A"));

                                        // Verify status name
                                        if let Some(status_name) = iggy.get("iggy.response.status_name") {
                                            assert_eq!(status_name.as_str(), Some("OK"), "Status name should be 'OK'");
                                        }

                                        // Verify response length (should be 4 for user_id u32)
                                        if let Some(length) = iggy.get("iggy.response.length") {
                                            assert_eq!(length.as_str(), Some("4"), "LoginUser response length should be 4");
                                            println!("  - Response length: 4");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(found_request, "LoginUser request (command 38) not found in capture");
        assert!(found_response, "LoginUser response (status 0, user_id) not found in capture");

        println!("\n✓ LoginUser dissection test passed - verified request and response");
        Ok(())
    }

    // 로컬 데이터에 토픽 있으면 302 에러남
    #[tokio::test]
    #[ignore]
    async fn test_create_topic_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing TCP CreateTopic (Command 302) Dissection ===");

        // Start packet capture (captures both TCP and QUIC)
        let capture = TsharkCapture::new(SERVER_IP)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create TCP client and login
        let client = create_test_tcp_client().await?;

        // Create a test stream first
        let stream_id = 1u32;
        let stream_name = "test_stream";
        println!("Creating test stream: {}", stream_name);
        client.create_stream(stream_name, Some(stream_id)).await?;

        // Create a topic
        let topic_name = "test_topic";
        let partitions_count = 3u32;
        println!("Sending CreateTopic command...");
        println!("  - Stream ID: {}", stream_id);
        println!("  - Topic name: {}", topic_name);
        println!("  - Partitions: {}", partitions_count);

        client
            .create_topic(
                &Identifier::numeric(stream_id)?,
                topic_name,
                partitions_count,
                CompressionAlgorithm::None,
                None, // replication_factor
                None, // topic_id (auto-assign)
                IggyExpiry::NeverExpire,
                MaxTopicSize::ServerDefault,
            )
            .await?;
        println!("CreateTopic successful");

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        println!("Total packets captured: {}", packets.len());
        println!("Iggy packets found: {}", iggy_packets.len());

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify we have both CreateTopic request and response
        let mut found_request = false;
        let mut found_response = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            // Check for CreateTopic request (command code 302)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "302" {
                        found_request = true;
                        println!("Packet {}: ✓ CreateTopic request found", idx);

                        // Verify command name
                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            assert_eq!(
                                cmd_name.as_str(),
                                Some("CreateTopic"),
                                "Command name should be 'CreateTopic'"
                            );
                            println!("  - Command name: CreateTopic");
                        }

                        // Verify request fields
                        if let Some(payload_tree) = iggy.get("iggy.request.payload_tree") {
                            // Stream ID
                            if let Some(stream_id_kind) =
                                payload_tree.get("iggy.create_topic.req.stream_id_kind")
                            {
                                println!(
                                    "  - Stream ID kind: {}",
                                    stream_id_kind.as_str().unwrap_or("N/A")
                                );
                            }

                            // Partitions count
                            if let Some(partitions) =
                                payload_tree.get("iggy.create_topic.req.partitions_count")
                            {
                                assert_eq!(
                                    partitions.as_str(),
                                    Some(partitions_count.to_string().as_str()),
                                    "Partitions count should match"
                                );
                                println!("  - Partitions count: {}", partitions_count);
                            }

                            // Topic name
                            if let Some(name) = payload_tree.get("iggy.create_topic.req.name") {
                                assert_eq!(
                                    name.as_str(),
                                    Some(topic_name),
                                    "Topic name should match"
                                );
                                println!("  - Topic name: {}", topic_name);
                            }

                            // Compression algorithm
                            if let Some(compression) =
                                payload_tree.get("iggy.create_topic.req.compression_algorithm")
                            {
                                println!(
                                    "  - Compression: {}",
                                    compression.as_str().unwrap_or("N/A")
                                );
                            }

                            // Message expiry
                            if let Some(expiry) =
                                payload_tree.get("iggy.create_topic.req.message_expiry")
                            {
                                println!("  - Message expiry: {}", expiry.as_str().unwrap_or("N/A"));
                            }

                            // Max topic size
                            if let Some(max_size) =
                                payload_tree.get("iggy.create_topic.req.max_topic_size")
                            {
                                println!("  - Max topic size: {}", max_size.as_str().unwrap_or("N/A"));
                            }
                        }
                    }
                }
            }

            // Check for CreateTopic response (status 0 with TopicDetails payload)
            if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                if cmd_name.as_str() == Some("CreateTopic") {
                    if let Some(status) = iggy.get("iggy.response.status") {
                        if let Some(status_val) = status.as_str() {
                            if status_val == "0" {
                                // Check if response has payload with topic details
                                if let Some(payload_tree) = iggy.get("iggy.response.payload_tree") {
                                    if let Some(resp_name) =
                                        payload_tree.get("iggy.create_topic.resp.name")
                                    {
                                        if resp_name.as_str() == Some(topic_name) {
                                            found_response = true;
                                            println!("Packet {}: ✓ CreateTopic response found", idx);
                                            println!("  - Status: OK (0)");

                                            // Verify status name
                                            if let Some(status_name) = iggy.get("iggy.response.status_name")
                                            {
                                                assert_eq!(
                                                    status_name.as_str(),
                                                    Some("OK"),
                                                    "Status name should be 'OK'"
                                                );
                                            }

                                            // Topic ID
                                            if let Some(topic_id) =
                                                payload_tree.get("iggy.create_topic.resp.topic_id")
                                            {
                                                println!(
                                                    "  - Topic ID: {}",
                                                    topic_id.as_str().unwrap_or("N/A")
                                                );
                                            }

                                            // Created At
                                            if let Some(created_at) =
                                                payload_tree.get("iggy.create_topic.resp.created_at")
                                            {
                                                println!(
                                                    "  - Created At: {}",
                                                    created_at.as_str().unwrap_or("N/A")
                                                );
                                            }

                                            // Partitions count
                                            if let Some(partitions) = payload_tree
                                                .get("iggy.create_topic.resp.partitions_count")
                                            {
                                                assert_eq!(
                                                    partitions.as_str(),
                                                    Some(partitions_count.to_string().as_str()),
                                                    "Response partitions count should match request"
                                                );
                                                println!("  - Partitions count: {}", partitions_count);
                                            }

                                            // Topic name
                                            println!("  - Topic name: {}", topic_name);

                                            // Size (should be 0 for new topic)
                                            if let Some(size) =
                                                payload_tree.get("iggy.create_topic.resp.size")
                                            {
                                                println!("  - Size: {}", size.as_str().unwrap_or("N/A"));
                                            }

                                            // Messages count (should be 0 for new topic)
                                            if let Some(messages_count) = payload_tree
                                                .get("iggy.create_topic.resp.messages_count")
                                            {
                                                println!(
                                                    "  - Messages count: {}",
                                                    messages_count.as_str().unwrap_or("N/A")
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(
            found_request,
            "CreateTopic request (command 302) not found in capture"
        );
        assert!(
            found_response,
            "CreateTopic response (status 0, TopicDetails) not found in capture"
        );

        println!("\n✓ CreateTopic dissection test passed - verified request and response");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_quic_ping_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing QUIC Ping (Command 1) Dissection ===");

        // Start packet capture (captures both TCP and QUIC)
        let capture = TsharkCapture::new(SERVER_IP)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create QUIC client (this will also send login, which is fine)
        let client = create_test_quic_client().await?;

        println!("Sending Ping command via QUIC...");
        client.ping().await?;

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        println!("Total packets captured: {}", packets.len());
        println!("Iggy packets found: {}", iggy_packets.len());

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify we have both Ping request and response
        let mut found_request = false;
        let mut found_response = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            // Check for Ping request (command code 1)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "1" {
                        found_request = true;
                        println!("Packet {}: ✓ Ping request found (QUIC)", idx);

                        // Verify command name
                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            assert_eq!(cmd_name.as_str(), Some("Ping"), "Command name should be 'Ping'");
                            println!("  - Command name: Ping");
                        }

                        // Verify request length (should be 4, only command code, no payload)
                        if let Some(length) = iggy.get("iggy.request.length") {
                            assert_eq!(length.as_str(), Some("4"), "Ping request length should be 4");
                            println!("  - Request length: 4");
                        }
                    }
                }
            }

            // Check for Ping response (status 0, no payload)
            if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                if cmd_name.as_str() == Some("Ping") {
                    if let Some(status) = iggy.get("iggy.response.status") {
                        if let Some(status_val) = status.as_str() {
                            if status_val == "0" {
                                // Check response length (should be 0 for Ping)
                                if let Some(length) = iggy.get("iggy.response.length") {
                                    if length.as_str() == Some("0") {
                                        found_response = true;
                                        println!("Packet {}: ✓ Ping response found (QUIC)", idx);
                                        println!("  - Status: OK (0)");
                                        println!("  - Response length: 0");

                                        // Verify status name
                                        if let Some(status_name) = iggy.get("iggy.response.status_name") {
                                            assert_eq!(status_name.as_str(), Some("OK"), "Status name should be 'OK'");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(found_request, "Ping request (command 1) not found in QUIC capture");
        assert!(found_response, "Ping response (status 0, length 0) not found in QUIC capture");

        println!("\n✓ QUIC Ping dissection test passed - verified request and response");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_quic_login_user_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing QUIC LoginUser (Command 38) Dissection ===");

        // Start packet capture (captures both TCP and QUIC)
        let capture = TsharkCapture::new(SERVER_IP)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create QUIC client without auto-login, then manually login
        let quic_config = QuicClientConfig {
            server_address: format!("{}:{}", SERVER_IP, SERVER_QUIC_PORT),
            server_name: "localhost".to_string(),
            ..Default::default()
        };

        let quic_client = QuicClient::create(Arc::new(quic_config))?;
        let client = IggyClient::new(ClientWrapper::Quic(quic_client));
        client.connect().await?;

        println!("Sending LoginUser command via QUIC...");
        client.login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD).await?;
        println!("Login successful");

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        println!("Total packets captured: {}", packets.len());
        println!("Iggy packets found: {}", iggy_packets.len());

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify we have both LoginUser request and response
        let mut found_request = false;
        let mut found_response = false;

        for (idx, packet) in iggy_packets.iter().enumerate() {
            let iggy = &packet["_source"]["layers"]["iggy"];

            // Check for LoginUser request (command code 38)
            if let Some(command) = iggy.get("iggy.request.command") {
                if let Some(cmd_val) = command.as_str() {
                    if cmd_val == "38" {
                        found_request = true;
                        println!("Packet {}: ✓ LoginUser request found (QUIC)", idx);

                        // Verify command name
                        if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                            assert_eq!(cmd_name.as_str(), Some("LoginUser"), "Command name should be 'LoginUser'");
                            println!("  - Command name: LoginUser");
                        }

                        // Verify username field
                        if let Some(username) = iggy.get("iggy.login_user.req.username") {
                            assert_eq!(username.as_str(), Some(DEFAULT_ROOT_USERNAME), "Username should match");
                            println!("  - Username: {}", DEFAULT_ROOT_USERNAME);
                        }

                        // Verify request has username length field
                        if let Some(username_len) = iggy.get("iggy.login_user.req.username_len") {
                            println!("  - Username length: {}", username_len.as_str().unwrap_or("N/A"));
                        }

                        // Verify request has password length field
                        if let Some(password_len) = iggy.get("iggy.login_user.req.password_len") {
                            println!("  - Password length: {}", password_len.as_str().unwrap_or("N/A"));
                        }
                    }
                }
            }

            // Check for LoginUser response (status 0 with user_id payload)
            if let Some(cmd_name) = iggy.get("iggy.request.command_name") {
                if cmd_name.as_str() == Some("LoginUser") {
                    if let Some(status) = iggy.get("iggy.response.status") {
                        if let Some(status_val) = status.as_str() {
                            if status_val == "0" {
                                // Check if response has payload_tree with user_id field
                                if let Some(payload_tree) = iggy.get("iggy.response.payload_tree") {
                                    if let Some(user_id) = payload_tree.get("iggy.login_user.resp.user_id") {
                                        found_response = true;
                                        println!("Packet {}: ✓ LoginUser response found (QUIC)", idx);
                                        println!("  - Status: OK (0)");
                                        println!("  - User ID: {}", user_id.as_str().unwrap_or("N/A"));

                                        // Verify status name
                                        if let Some(status_name) = iggy.get("iggy.response.status_name") {
                                            assert_eq!(status_name.as_str(), Some("OK"), "Status name should be 'OK'");
                                        }

                                        // Verify response length (should be 4 for user_id u32)
                                        if let Some(length) = iggy.get("iggy.response.length") {
                                            assert_eq!(length.as_str(), Some("4"), "LoginUser response length should be 4");
                                            println!("  - Response length: 4");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(found_request, "LoginUser request (command 38) not found in QUIC capture");
        assert!(found_response, "LoginUser response (status 0, user_id) not found in QUIC capture");

        println!("\n✓ QUIC LoginUser dissection test passed - verified request and response");
        Ok(())
    }
}
