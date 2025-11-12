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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::sleep;

    /// Default credentials for Iggy server
    const DEFAULT_ROOT_USERNAME: &str = "iggy";
    const DEFAULT_ROOT_PASSWORD: &str = "iggy";

    /// Server configuration - change these constants to match your server setup
    const SERVER_IP: &str = "127.0.0.1";
    const SERVER_TCP_PORT: u16 = 8090;

    /// Timing constants for packet capture tests
    const CAPTURE_START_WAIT_MS: u64 = 1000;
    const OPERATION_WAIT_MS: u64 = 2000;
    const CAPTURE_STOP_WAIT_MS: u64 = 500;

    /// Atomic counter for generating unique file IDs
    static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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
        tshark_process: Option<Child>,
    }

    impl TsharkCapture {
        fn new(ip: &str, port: u16) -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let pid = std::process::id();
            let counter = FILE_COUNTER.fetch_add(1, Ordering::SeqCst);

            let file = format!("/tmp/iggy_test_{}_{}_{}.pcap", timestamp, pid, counter);
            let pcap_file = PathBuf::from(file);

            Self {
                ip: ip.to_string(),
                port,
                pcap_file,
                tshark_process: None,
            }
        }

        fn capture(&mut self) -> io::Result<()> {
            // Find dissector.lua in the workspace root
            let dissector_path = std::env::current_dir()?.join("dissector.lua");

            if !dissector_path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Dissector not found at: {}", dissector_path.display()),
                ));
            }

            let lua_script_arg = format!("lua_script:{}", dissector_path.display());
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

            let process = command.spawn()?;
            self.tshark_process = Some(process);
            Ok(())
        }

        fn stop(&mut self) {
            if let Some(mut process) = self.tshark_process.take() {
                let _ = process.kill();
            }
        }

        fn analyze(&self) -> io::Result<Vec<Value>> {
            // Find dissector.lua in the workspace root
            let dissector_path = std::env::current_dir()?.join("dissector.lua");

            if !dissector_path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Dissector not found at: {}", dissector_path.display()),
                ));
            }

            let lua_script_arg = format!("lua_script:{}", dissector_path.display());
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

            let packets: Vec<Value> = serde_json::from_str(&json_str)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
        client: IggyClient,
    }

    impl TestFixture {
        /// Create a new test fixture (does not start capture or connect client)
        ///
        /// Call `setup()` to begin packet capture and connect the client.
        fn new() -> Self {
            let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT);

            let tcp_config = TcpClientConfig {
                server_address: format!("{}:{}", SERVER_IP, SERVER_TCP_PORT),
                ..Default::default()
            };

            let tcp_client =
                TcpClient::create(Arc::new(tcp_config)).expect("Failed to create TCP client");
            let client = IggyClient::new(ClientWrapper::Tcp(tcp_client));

            Self { capture, client }
        }

        /// Setup test fixture: start packet capture and connect client
        async fn start(&mut self, login: bool) -> Result<(), Box<dyn std::error::Error>> {
            // Start tshark capture
            self.capture.capture()?;
            sleep(Duration::from_millis(CAPTURE_START_WAIT_MS)).await;

            // Connect client
            self.client.connect().await?;

            // Login if requested
            if login {
                self.client
                    .login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD)
                    .await?;
            }

            Ok(())
        }

        /// Stop packet capture and analyze captured packets
        async fn stop_and_analyze(&mut self) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
            sleep(Duration::from_secs(OPERATION_WAIT_MS)).await;

            self.capture.stop();
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

    /// Helper function to extract iggy packets from tshark output
    fn extract_iggy_packets(packets: &[Value]) -> Vec<&Value> {
        packets
            .iter()
            .filter(|p| p["_source"]["layers"].get("iggy").is_some())
            .collect()
    }

    /// Find and verify request packet by command ID and common fields
    /// Returns the entire iggy packet layer for further inspection
    fn verify_request_packet<'a>(
        iggy_packets: &[&'a Value],
        command_id: u32,
        command_name: &str,
        expected_length: u32,
    ) -> Result<&'a Value, Box<dyn std::error::Error>> {
        // Find the request packet
        let iggy = iggy_packets
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
            })?;

        // Verify common fields
        let cmd_name: String = expect_iggy_field(iggy, "iggy.request.command_name");
        assert_eq!(cmd_name, command_name);

        let length: u32 = expect_iggy_field(iggy, "iggy.request.length");
        assert_eq!(length, expected_length);

        Ok(iggy)
    }

    /// Find and verify response packet by command name, status code, and common fields
    /// Returns the entire iggy packet layer for further inspection
    fn verify_response_packet<'a>(
        iggy_packets: &[&'a Value],
        command_name: &str,
        expected_status_code: u32,
        expected_length: Option<u32>,
    ) -> Result<&'a Value, Box<dyn std::error::Error>> {
        // Find the response packet
        let iggy = iggy_packets
            .iter()
            .find_map(|packet| {
                let iggy = &packet["_source"]["layers"]["iggy"];
                let cmd_name: String = get_iggy_field(iggy, "iggy.request.command_name").ok()?;
                let pkt_status: u32 = get_iggy_field(iggy, "iggy.response.status").ok()?;
                (cmd_name == command_name && pkt_status == expected_status_code).then_some(iggy)
            })
            .ok_or_else(|| {
                format!(
                    "{} response (status {}) not found in capture",
                    command_name, expected_status_code
                )
            })?;

        // Verify status name (0 = OK, non-zero = error)
        let status_name: String = expect_iggy_field(iggy, "iggy.response.status_name");
        let expected_status_name = if expected_status_code == 0 {
            "OK"
        } else {
            // For error cases, you might want to be more flexible
            &status_name
        };
        assert_eq!(status_name, expected_status_name);

        // Verify length if specified
        if let Some(len) = expected_length {
            let length: u32 = expect_iggy_field(iggy, "iggy.response.length");
            assert_eq!(length, len);
        }

        Ok(iggy)
    }

    fn get_request_payload(packet: &Value) -> Option<&Value> {
        packet.get("iggy.request.payload_tree")
    }

    fn get_response_payload(packet: &Value) -> Option<&Value> {
        packet.get("iggy.response.payload_tree")
    }

    /// Helper function to print packet details for debugging
    fn print_packet_json(packets: &[Value], show_all: bool) {
        println!("\n=== Captured Packets JSON ===");

        for (idx, packet) in packets.iter().enumerate() {
            println!("\n--- Packet {} ---", idx);

            if show_all {
                let json = serde_json::to_string_pretty(packet)
                    .unwrap_or_else(|_| "Error serializing packet".to_string());
                println!("{}", json);
            } else if let Some(iggy) = packet["_source"]["layers"].get("iggy") {
                println!("\nIggy Protocol:");
                let json =
                    serde_json::to_string_pretty(iggy).unwrap_or_else(|_| "Error".to_string());
                println!("{}", json);
            }
        }
        println!("\n=== End of Packets ===\n");
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_dissection() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = TestFixture::new();
        fixture.start(true).await?;

        fixture.client.ping().await?;

        let packets = fixture.stop_and_analyze().await?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Verify Ping request
        let req = verify_request_packet(&iggy_packets, 1, "Ping", 4)?;

        let command: u32 = expect_iggy_field(req, "iggy.request.command");
        assert_eq!(command, 1);

        let command_name: String = expect_iggy_field(req, "iggy.request.command_name");
        assert_eq!(command_name, "Ping");

        let length: u32 = expect_iggy_field(req, "iggy.request.length");
        assert_eq!(length, 4);

        assert!(
            get_request_payload(req).is_none(),
            "Ping request should not have payload"
        );

        // Verify Ping response
        let resp = verify_response_packet(&iggy_packets, "Ping", 0, Some(0))?;

        let status: u32 = expect_iggy_field(resp, "iggy.response.status");
        assert_eq!(status, 0);

        let status_name: String = expect_iggy_field(resp, "iggy.response.status_name");
        assert_eq!(status_name, "OK");

        let resp_length: u32 = expect_iggy_field(resp, "iggy.response.length");
        assert_eq!(resp_length, 0);

        assert!(
            get_response_payload(resp).is_none(),
            "Ping response should not have payload"
        );

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_login_user_dissection() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = TestFixture::new();
        fixture.start(false).await?;

        fixture
            .client
            .login_user(DEFAULT_ROOT_USERNAME, DEFAULT_ROOT_PASSWORD)
            .await?;

        let packets = fixture.stop_and_analyze().await?;
        let iggy_packets = extract_iggy_packets(&packets);

        // Verify LoginUser request
        let req = verify_request_packet(&iggy_packets, 38, "LoginUser", 27)?;

        let command: u32 = expect_iggy_field(req, "iggy.request.command");
        assert_eq!(command, 38);

        let command_name: String = expect_iggy_field(req, "iggy.request.command_name");
        assert_eq!(command_name, "LoginUser");

        let length: u32 = expect_iggy_field(req, "iggy.request.length");
        assert_eq!(length, 27);

        let req_payload = get_request_payload(req).expect("LoginUser request should have payload");

        let username: String = expect_iggy_field(req_payload, "iggy.login_user.req.username");
        assert_eq!(username, DEFAULT_ROOT_USERNAME);

        let username_len: u32 =
            expect_iggy_field(req_payload, "iggy.login_user.req.username_len");
        assert_eq!(username_len, DEFAULT_ROOT_USERNAME.len() as u32);

        let password_len: u32 =
            expect_iggy_field(req_payload, "iggy.login_user.req.password_len");
        assert_eq!(password_len, DEFAULT_ROOT_PASSWORD.len() as u32);

        // Verify LoginUser response
        let resp = verify_response_packet(&iggy_packets, "LoginUser", 0, Some(4))?;

        let status: u32 = expect_iggy_field(resp, "iggy.response.status");
        assert_eq!(status, 0);

        let status_name: String = expect_iggy_field(resp, "iggy.response.status_name");
        assert_eq!(status_name, "OK");

        let resp_length: u32 = expect_iggy_field(resp, "iggy.response.length");
        assert_eq!(resp_length, 4);

        let resp_payload = get_response_payload(resp)
            .expect("LoginUser response should have payload");

        let user_id: u32 = expect_iggy_field(resp_payload, "iggy.login_user.resp.user_id");
        assert!(user_id > 0, "User ID should be greater than 0");

        Ok(())
    }

    // 로컬 데이터에 토픽 있으면 302 에러남
    #[tokio::test]
    #[ignore]
    async fn test_create_topic_dissection() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = TestFixture::new();
        fixture.start(true).await?;

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
        let req = verify_request_packet(&iggy_packets, 302, "CreateTopic", 47)?;

        let command: u32 = expect_iggy_field(req, "iggy.request.command");
        assert_eq!(command, 302);

        let command_name: String = expect_iggy_field(req, "iggy.request.command_name");
        assert_eq!(command_name, "CreateTopic");

        let length: u32 = expect_iggy_field(req, "iggy.request.length");
        assert_eq!(length, 47);

        let req_payload = get_request_payload(req).expect("CreateTopic request should have payload");

        let req_stream_id_kind: u32 = expect_iggy_field(req_payload, "iggy.create_topic.req.stream_id_kind");
        assert_eq!(req_stream_id_kind, 1); // 1 = numeric identifier

        let req_stream_id_length: u32 = expect_iggy_field(req_payload, "iggy.create_topic.req.stream_id_length");
        assert_eq!(req_stream_id_length, 4); // u32 = 4 bytes

        let req_stream_id_value: u32 = expect_iggy_field(req_payload, "iggy.create_topic.req.stream_id_value_numeric");
        assert_eq!(req_stream_id_value, stream_id);

        let name: String = expect_iggy_field(req_payload, "iggy.create_topic.req.name");
        assert_eq!(name, topic_name);

        let name_len: u32 = expect_iggy_field(req_payload, "iggy.create_topic.req.name_len");
        assert_eq!(name_len, topic_name.len() as u32);

        let partitions: u32 = expect_iggy_field(req_payload, "iggy.create_topic.req.partitions_count");
        assert_eq!(partitions, partitions_count);

        // Verify CreateTopic response
        let resp = verify_response_packet(&iggy_packets, "CreateTopic", 0, None)?;

        let status: u32 = expect_iggy_field(resp, "iggy.response.status");
        assert_eq!(status, 0);

        let status_name: String = expect_iggy_field(resp, "iggy.response.status_name");
        assert_eq!(status_name, "OK");

        let resp_payload = get_response_payload(resp)
            .expect("CreateTopic response should have payload");

        let resp_topic_id: u32 = expect_iggy_field(resp_payload, "iggy.create_topic.resp.topic_id");
        assert!(resp_topic_id > 0, "Topic ID should be greater than 0");

        let resp_name: String = expect_iggy_field(resp_payload, "iggy.create_topic.resp.name");
        assert_eq!(resp_name, topic_name);

        let resp_name_len: u32 = expect_iggy_field(resp_payload, "iggy.create_topic.resp.name_len");
        assert_eq!(resp_name_len, topic_name.len() as u32);

        let resp_partitions: u32 = expect_iggy_field(resp_payload, "iggy.create_topic.resp.partitions_count");
        assert_eq!(resp_partitions, partitions_count);

        let resp_messages_count: u32 = expect_iggy_field(resp_payload, "iggy.create_topic.resp.messages_count");
        assert_eq!(resp_messages_count, 0);

        let resp_size: u32 = expect_iggy_field(resp_payload, "iggy.create_topic.resp.size");
        assert_eq!(resp_size, 0);

        Ok(())
    }
}
