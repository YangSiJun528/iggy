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
            let dissector_path = std::env::current_dir()?.join("dissector.lua");

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
            let lua_script_arg = format!("lua_script:{}", self.dissector_path.display());
            let port_config_arg = format!("iggy.server_port:{}", self.port);
            let filter_arg = format!("tcp and host {} and port {}", self.ip, self.port);

            let mut command = ProcessCommand::new("tshark");

            command
                .args([
                    "-i",
                    "lo",
                    "-w",
                    self.pcap_file.to_str().unwrap(),
                    "-f",
                    &filter_arg,
                    "-X",
                    &lua_script_arg,
                    "-o",
                    &port_config_arg,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            command.spawn()
        }

        fn analyze(&self) -> io::Result<Vec<Value>> {
            let lua_script_arg = format!("lua_script:{}", self.dissector_path.display());
            let port_config_arg = format!("iggy.server_port:{}", self.port);

            let output = ProcessCommand::new("tshark")
                .args([
                    "-r",
                    self.pcap_file.to_str().unwrap(),
                    "-Y",
                    "iggy",
                    "-T",
                    "json",
                    "-X",
                    &lua_script_arg,
                    "-o",
                    &port_config_arg,
                    "-V", // Verbose output
                ])
                .output()?;

            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("tshark failed: {}", String::from_utf8_lossy(&output.stderr)),
                ));
            }

            let json_str = String::from_utf8_lossy(&output.stdout);

            if json_str.trim().is_empty() {
                return Ok(Vec::new());
            }

            let packets: Vec<Value> = serde_json::from_str(&json_str).map_err(|e| {
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
        client
            .login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD)
            .await?;

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
                println!(
                    "{}",
                    serde_json::to_string_pretty(packet)
                        .unwrap_or_else(|_| "Error serializing packet".to_string())
                );
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
                        println!(
                            "{}",
                            serde_json::to_string_pretty(iggy)
                                .unwrap_or_else(|_| "Error".to_string())
                        );
                    }
                }
            }
        }
        println!("\n=== End of Packets ===\n");
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_dissection() -> Result<(), Box<dyn std::error::Error>> {
        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client (this will also send login, which is fine)
        let client = create_test_client().await?;

        client.ping().await?;

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify Ping request
        let (_idx, iggy) = iggy_packets
            .iter()
            .enumerate()
            .find_map(|(idx, packet)| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let command = iggy.get("iggy.request.command")?.as_str()?;
                (command == "1").then_some((idx, iggy))
            })
            .expect("Ping request (command 1) not found in capture");

        let cmd_name = iggy
            .get("iggy.request.command_name")
            .and_then(|v| v.as_str())
            .expect("Command name field missing");
        assert_eq!(cmd_name, "Ping", "Command name should be 'Ping'");

        let length = iggy
            .get("iggy.request.length")
            .and_then(|v| v.as_str())
            .expect("Request length field missing");
        assert_eq!(length, "4", "Ping request length should be 4");

        // Verify Ping response
        let (_idx, iggy) = iggy_packets
            .iter()
            .enumerate()
            .find_map(|(idx, packet)| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let cmd_name = iggy.get("iggy.request.command_name")?.as_str()?;
                let status = iggy.get("iggy.response.status")?.as_str()?;
                (cmd_name == "Ping" && status == "0").then_some((idx, iggy))
            })
            .expect("Ping response (status 0, length 0) not found in capture");

        let resp_length = iggy
            .get("iggy.response.length")
            .and_then(|v| v.as_str())
            .expect("Response length field missing");
        assert_eq!(resp_length, "0", "Ping response length should be 0");

        let status_name = iggy
            .get("iggy.response.status_name")
            .and_then(|v| v.as_str())
            .expect("Status name field missing");
        assert_eq!(status_name, "OK", "Status name should be 'OK'");

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_login_user_dissection() -> Result<(), Box<dyn std::error::Error>> {
        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
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

        client
            .login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD)
            .await?;

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify LoginUser request
        let (_idx, iggy) = iggy_packets
            .iter()
            .enumerate()
            .find_map(|(idx, packet)| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let command = iggy.get("iggy.request.command")?.as_str()?;
                (command == "38").then_some((idx, iggy))
            })
            .expect("LoginUser request (command 38) not found in capture");

        let cmd_name = iggy
            .get("iggy.request.command_name")
            .and_then(|v| v.as_str())
            .expect("Command name field missing");
        assert_eq!(cmd_name, "LoginUser", "Command name should be 'LoginUser'");

        let payload_tree = iggy
            .get("iggy.request.payload_tree")
            .expect("Request payload_tree missing");

        let username = payload_tree
            .get("iggy.login_user.req.username")
            .and_then(|v| v.as_str())
            .expect("Username field missing");
        assert_eq!(username, DEFAULT_ROOT_USERNAME, "Username should match");

        // Verify LoginUser response
        let (_idx, iggy) = iggy_packets
            .iter()
            .enumerate()
            .find_map(|(idx, packet)| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let cmd_name = iggy.get("iggy.request.command_name")?.as_str()?;
                let status = iggy.get("iggy.response.status")?.as_str()?;
                (cmd_name == "LoginUser" && status == "0").then_some((idx, iggy))
            })
            .expect("LoginUser response (status 0, user_id) not found in capture");

        let payload_tree = iggy
            .get("iggy.response.payload_tree")
            .expect("Response payload_tree missing");

        let _user_id = payload_tree
            .get("iggy.login_user.resp.user_id")
            .and_then(|v| v.as_str())
            .expect("User ID field missing");

        let status_name = iggy
            .get("iggy.response.status_name")
            .and_then(|v| v.as_str())
            .expect("Status name field missing");
        assert_eq!(status_name, "OK", "Status name should be 'OK'");

        let length = iggy
            .get("iggy.response.length")
            .and_then(|v| v.as_str())
            .expect("Response length field missing");
        assert_eq!(length, "4", "LoginUser response length should be 4");

        Ok(())
    }

    // 로컬 데이터에 토픽 있으면 302 에러남
    #[tokio::test]
    #[ignore]
    async fn test_create_topic_dissection() -> Result<(), Box<dyn std::error::Error>> {
        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client and login
        let client = create_test_client().await?;

        // Create a test stream first
        let stream_id = 1u32;
        let stream_name = "test_stream";
        client.create_stream(stream_name, Some(stream_id)).await?;

        // Create a topic
        let topic_name = "test_topic";
        let partitions_count = 3u32;

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

        // Wait for packets to be captured
        sleep(Duration::from_secs(2)).await;

        // Stop capture and analyze
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        let packets = capture.analyze()?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Print packet JSON for debugging
        print_packet_json(&packets, false);

        if iggy_packets.is_empty() {
            return Err("No Iggy packets captured".into());
        }

        // Verify CreateTopic request
        let (_idx, iggy) = iggy_packets
            .iter()
            .enumerate()
            .find_map(|(idx, packet)| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let command = iggy.get("iggy.request.command")?.as_str()?;
                (command == "302").then_some((idx, iggy))
            })
            .expect("CreateTopic request (command 302) not found in capture");

        let cmd_name = iggy
            .get("iggy.request.command_name")
            .and_then(|v| v.as_str())
            .expect("Command name field missing");
        assert_eq!(
            cmd_name, "CreateTopic",
            "Command name should be 'CreateTopic'"
        );

        let payload_tree = iggy
            .get("iggy.request.payload_tree")
            .expect("Request payload_tree missing");

        let partitions = payload_tree
            .get("iggy.create_topic.req.partitions_count")
            .and_then(|v| v.as_str())
            .expect("Partitions count field missing");
        assert_eq!(
            partitions,
            partitions_count.to_string().as_str(),
            "Partitions count should match"
        );

        let name = payload_tree
            .get("iggy.create_topic.req.name")
            .and_then(|v| v.as_str())
            .expect("Topic name field missing");
        assert_eq!(name, topic_name, "Topic name should match");

        // Verify CreateTopic response
        let (_idx, iggy) = iggy_packets
            .iter()
            .enumerate()
            .find_map(|(idx, packet)| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let cmd_name = iggy.get("iggy.request.command_name")?.as_str()?;
                let status = iggy.get("iggy.response.status")?.as_str()?;
                (cmd_name == "CreateTopic" && status == "0").then_some((idx, iggy))
            })
            .expect("CreateTopic response (status 0, TopicDetails) not found in capture");

        let status_name = iggy
            .get("iggy.response.status_name")
            .and_then(|v| v.as_str())
            .expect("Status name field missing");
        assert_eq!(status_name, "OK", "Status name should be 'OK'");

        let payload_tree = iggy
            .get("iggy.response.payload_tree")
            .expect("Response payload_tree missing");

        let resp_name = payload_tree
            .get("iggy.create_topic.resp.name")
            .and_then(|v| v.as_str())
            .expect("Response topic name field missing");
        assert_eq!(resp_name, topic_name, "Response topic name should match");

        let resp_partitions = payload_tree
            .get("iggy.create_topic.resp.partitions_count")
            .and_then(|v| v.as_str())
            .expect("Response partitions count field missing");
        assert_eq!(
            resp_partitions,
            partitions_count.to_string().as_str(),
            "Response partitions count should match request"
        );

        Ok(())
    }
}
