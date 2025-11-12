#[cfg(test)]
mod tests {
    use iggy::prelude::*;
    use serde_json::Value;
    use std::fmt::Display;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Default credentials for Iggy server
    const DEFAULT_ROOT_USERNAME: &str = "iggy";
    const DEFAULT_ROOT_PASSWORD: &str = "iggy";

    /// Server configuration - change these constants to match your server setup
    const SERVER_IP: &str = "127.0.0.1";
    const SERVER_TCP_PORT: u16 = 8090;

    /// Timing constants for packet capture tests
    const CAPTURE_START_WAIT_MS: u64 = 1000;
    const OPERATION_WAIT_SECS: u64 = 2;
    const CAPTURE_STOP_WAIT_MS: u64 = 500;

    /// Helper function to extract and parse iggy field values (returns Result)
    fn get_iggy_field<T>(iggy: &Value, field: &str) -> Result<T, String>
    where
        T: FromStr,
        T::Err: Display,
    {
        iggy.get(field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{} field missing", field))?
            .parse::<T>()
            .map_err(|e| format!("Failed to parse {}: {}", field, e))
    }

    /// Helper function to extract and parse iggy field values (panics on error)
    fn expect_iggy_field<T>(iggy: &Value, field: &str) -> T
    where
        T: FromStr,
        T::Err: Display,
    {
        get_iggy_field(iggy, field).unwrap_or_else(|e| panic!("{}", e))
    }

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

    /// Test fixture that manages tshark capture and client lifecycle
    struct TestFixture {
        capture: TsharkCapture,
        tshark_process: Option<Child>,
        client: IggyClient,
    }

    impl TestFixture {
        /// Create a new test fixture with automatic login
        async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
            let tshark = capture.start()?;
            sleep(Duration::from_millis(CAPTURE_START_WAIT_MS)).await;

            let client = create_test_client().await?;

            Ok(Self {
                capture,
                tshark_process: Some(tshark),
                client,
            })
        }

        /// Create a new test fixture without automatic login (for login-specific tests)
        async fn new_without_auto_login() -> Result<Self, Box<dyn std::error::Error>> {
            let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
            let tshark = capture.start()?;
            sleep(Duration::from_millis(CAPTURE_START_WAIT_MS)).await;

            // Create client without login for login-specific tests
            let tcp_config = TcpClientConfig {
                server_address: format!("{}:{}", SERVER_IP, SERVER_TCP_PORT),
                ..Default::default()
            };
            let tcp_client = TcpClient::create(Arc::new(tcp_config))?;
            let client = IggyClient::new(ClientWrapper::Tcp(tcp_client));
            client.connect().await?;

            Ok(Self {
                capture,
                tshark_process: Some(tshark),
                client,
            })
        }

        /// Stop packet capture and analyze captured packets
        async fn stop_and_analyze(&mut self) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            sleep(Duration::from_secs(OPERATION_WAIT_SECS)).await;

            if let Some(mut tshark) = self.tshark_process.take() {
                let _ = tshark.kill();
            }
            sleep(Duration::from_millis(CAPTURE_STOP_WAIT_MS)).await;

            let packets = self.capture.analyze()?;
            let iggy_packets = extract_iggy_packets(&packets);

            print_packet_json(&packets, false);

            if iggy_packets.is_empty() {
                return Err("No Iggy packets captured".into());
            }

            Ok(packets)
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

    /// Find request packet by command ID
    fn find_request_packet<'a>(
        iggy_packets: &[&'a Value],
        command_id: u32,
        command_name: &str,
    ) -> Result<&'a Value, String> {
        iggy_packets
            .iter()
            .find_map(|packet| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let command: u32 = get_iggy_field(iggy, "iggy.request.command").ok()?;
                (command == command_id).then_some(iggy)
            })
            .ok_or_else(|| {
                format!(
                    "{} request (command {}) not found in capture",
                    command_name, command_id
                )
            })
    }

    /// Find response packet by command name and status
    fn find_response_packet<'a>(
        iggy_packets: &[&'a Value],
        command_name: &str,
        status: u32,
    ) -> Result<&'a Value, String> {
        iggy_packets
            .iter()
            .find_map(|packet| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let cmd_name: String = get_iggy_field(iggy, "iggy.request.command_name").ok()?;
                let pkt_status: u32 = get_iggy_field(iggy, "iggy.response.status").ok()?;
                (cmd_name == command_name && pkt_status == status).then_some(iggy)
            })
            .ok_or_else(|| {
                format!(
                    "{} response (status {}) not found in capture",
                    command_name, status
                )
            })
    }

    /// Verify basic request fields
    fn verify_request_basics(
        iggy: &Value,
        expected_command: &str,
        expected_length: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cmd_name: String = expect_iggy_field(iggy, "iggy.request.command_name");
        assert_eq!(cmd_name, expected_command);

        let length: u32 = expect_iggy_field(iggy, "iggy.request.length");
        assert_eq!(length, expected_length);

        Ok(())
    }

    /// Verify basic response fields
    fn verify_response_basics(
        iggy: &Value,
        expected_status: &str,
        expected_length: Option<u32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status_name: String = expect_iggy_field(iggy, "iggy.response.status_name");
        assert_eq!(status_name, expected_status);

        if let Some(len) = expected_length {
            let length: u32 = expect_iggy_field(iggy, "iggy.response.length");
            assert_eq!(length, len);
        }

        Ok(())
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
        let mut fixture = TestFixture::new().await?;

        fixture.client.ping().await?;

        let packets = fixture.stop_and_analyze().await?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Verify Ping request
        let iggy = find_request_packet(&iggy_packets, 1, "Ping")?;
        verify_request_basics(iggy, "Ping", 4)?;

        // Verify Ping response
        let iggy = find_response_packet(&iggy_packets, "Ping", 0)?;
        verify_response_basics(iggy, "OK", Some(0))?;

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_login_user_dissection() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = TestFixture::new_without_auto_login().await?;

        fixture
            .client
            .login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD)
            .await?;

        let packets = fixture.stop_and_analyze().await?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Verify LoginUser request
        let iggy = find_request_packet(&iggy_packets, 38, "LoginUser")?;

        let payload_tree = iggy
            .get("iggy.request.payload_tree")
            .expect("Request payload_tree missing");

        let username: String = expect_iggy_field(payload_tree, "iggy.login_user.req.username");
        assert_eq!(username, DEFAULT_ROOT_USERNAME);

        // Verify LoginUser response
        let iggy = find_response_packet(&iggy_packets, "LoginUser", 0)?;
        verify_response_basics(iggy, "OK", Some(4))?;

        let payload_tree = iggy
            .get("iggy.response.payload_tree")
            .expect("Response payload_tree missing");

        let _user_id: u32 = expect_iggy_field(payload_tree, "iggy.login_user.resp.user_id");

        Ok(())
    }

    // 로컬 데이터에 토픽 있으면 302 에러남
    #[tokio::test]
    #[ignore]
    async fn test_create_topic_dissection() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = TestFixture::new().await?;

        // Create a test stream first
        let stream_id = 1u32;
        let stream_name = "test_stream";
        fixture
            .client
            .create_stream(stream_name, Some(stream_id))
            .await?;

        // Create a topic
        let topic_name = "test_topic";
        let partitions_count = 3u32;

        fixture
            .client
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

        let packets = fixture.stop_and_analyze().await?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Verify CreateTopic request
        let iggy = find_request_packet(&iggy_packets, 302, "CreateTopic")?;

        let payload_tree = iggy
            .get("iggy.request.payload_tree")
            .expect("Request payload_tree missing");

        let partitions: u32 =
            expect_iggy_field(payload_tree, "iggy.create_topic.req.partitions_count");
        assert_eq!(partitions, partitions_count);

        let name: String = expect_iggy_field(payload_tree, "iggy.create_topic.req.name");
        assert_eq!(name, topic_name);

        // Verify CreateTopic response
        let iggy = find_response_packet(&iggy_packets, "CreateTopic", 0)?;
        verify_response_basics(iggy, "OK", None)?;

        let payload_tree = iggy
            .get("iggy.response.payload_tree")
            .expect("Response payload_tree missing");

        let resp_name: String = expect_iggy_field(payload_tree, "iggy.create_topic.resp.name");
        assert_eq!(resp_name, topic_name);

        let resp_partitions: u32 =
            expect_iggy_field(payload_tree, "iggy.create_topic.resp.partitions_count");
        assert_eq!(resp_partitions, partitions_count);

        Ok(())
    }
}
