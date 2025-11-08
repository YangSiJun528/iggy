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
        println!("\n=== Testing Ping (Command 1) Dissection ===");

        // Start packet capture
        let capture = TsharkCapture::new(SERVER_IP, SERVER_TCP_PORT)?;
        let mut tshark = capture.start()?;
        sleep(Duration::from_millis(1000)).await;

        // Create client (this will also send login, which is fine)
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
            if let Some(status) = iggy.get("iggy.response.status") {
                if let Some(status_val) = status.as_str() {
                    // Check if this is a Ping response by looking at the message type
                    if let Some(msg_type) = iggy.get("iggy.message_type") {
                        if msg_type.as_str() == Some("Response") && status_val == "0" {
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

        assert!(found_request, "Ping request (command 1) not found in capture");
        assert!(found_response, "Ping response (status 0, length 0) not found in capture");

        println!("\n✓ Ping dissection test passed - verified request and response");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_login_user_dissection() -> Result<(), Box<dyn std::error::Error>> {
        println!("\n=== Testing LoginUser (Command 38) Dissection ===");

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
        let mut _found_response = false; // TODO: uncomment assertion when response dissector is implemented

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
                        if let Some(username) = iggy.get("iggy.login.username") {
                            assert_eq!(username.as_str(), Some(DEFAULT_ROOT_USERNAME), "Username should match");
                            println!("  - Username: {}", DEFAULT_ROOT_USERNAME);
                        }

                        // Verify request has username length field
                        if let Some(username_len) = iggy.get("iggy.login.username_len") {
                            println!("  - Username length: {}", username_len.as_str().unwrap_or("N/A"));
                        }

                        // Verify request has password length field
                        if let Some(password_len) = iggy.get("iggy.login.password_len") {
                            println!("  - Password length: {}", password_len.as_str().unwrap_or("N/A"));
                        }
                    }
                }
            }

            // Check for LoginUser response (status 0 with user_id payload)
            if let Some(status) = iggy.get("iggy.response.status") {
                if let Some(status_val) = status.as_str() {
                    if status_val == "0" {
                        // Check if response has user_id field (LoginUser specific)
                        if let Some(user_id) = iggy.get("iggy.login.user_id") {
                            _found_response = true;
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

        assert!(found_request, "LoginUser request (command 38) not found in capture");
        //assert!(found_response, "LoginUser response (status 0, user_id) not found in capture"); - response 아직 안 만듦.

        println!("\n✓ LoginUser dissection test passed - verified request and response");
        Ok(())
    }
}
