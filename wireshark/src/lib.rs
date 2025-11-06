#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use iggy_common::ping::Ping;
    use serde_json::Value;
    use server::binary::command::ServerCommand;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    /// Creates a request packet from a ServerCommand
    /// Format: LENGTH(4) + COMMAND_CODE(4) + PAYLOAD(N)
    /// where LENGTH = 4 + payload_length
    fn create_request_packet(command: &ServerCommand) -> Vec<u8> {
        let bytes = command.to_bytes();
        let mut buf = BytesMut::with_capacity(4 + bytes.len());
        buf.put_u32_le(bytes.len() as u32);
        buf.put_slice(&bytes);
        buf.to_vec()
    }

    /// Creates a response packet
    /// Format: STATUS(4) + LENGTH(4) + PAYLOAD(N)
    /// where LENGTH = payload length (0 for error responses)
    fn create_response_packet(status: u32, payload: &[u8]) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(8 + payload.len());
        buf.put_u32_le(status); // STATUS
        buf.put_u32_le(payload.len() as u32); // LENGTH
        buf.put_slice(payload); // PAYLOAD
        buf.to_vec()
    }

    /// Creates a success response packet (status = 0)
    fn create_success_response(payload: &[u8]) -> Vec<u8> {
        create_response_packet(0, payload)
    }

    /// Creates an error response packet (status != 0, length = 0)
    fn create_error_response(status: u32) -> Vec<u8> {
        create_response_packet(status, &[])
    }

    struct TsharkCapture {
        ip: String,
        port: u16,
        pcap_file: PathBuf,
        dissector_path: PathBuf,
    }

    impl TsharkCapture {
        fn new(ip: &str, port: u16) -> io::Result<Self> {
            let file = format!("/tmp/iggy_test_{}.pcap", port);

            // 다양한 가능한 Lua 스크립트 위치 확인
            let dissector_path = std::env::current_dir()?.join("dissector.lua");

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

            // Lua 스크립트와 포트 설정 추가
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
                    "-V", // 자세한 출력 추가
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

    /// A dummy server that responds to requests
    async fn run_dummy_server(ip: &str, port: u16) -> io::Result<()> {
        let listener = TcpListener::bind(format!("{}:{}", ip, port)).await?;
        println!("Dummy server listening on {}:{}", ip, port);

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                println!("Dummy server accepted connection");
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];

                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) => {
                                println!("Connection closed by client");
                                break;
                            }
                            Ok(n) => {
                                println!("Dummy server received {} bytes", n);

                                // Parse request and send response
                                if n >= 8 {
                                    // Read LENGTH and COMMAND_CODE
                                    let length = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                                    let command_code = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

                                    println!("  LENGTH: {}, COMMAND_CODE: {}", length, command_code);

                                    // Send response based on command
                                    let response = match command_code {
                                        1 => {
                                            // Ping: success response with empty payload
                                            println!("  Responding to Ping with success");
                                            create_success_response(&[])
                                        }
                                        10 => {
                                            // GetStats: success response with dummy stats
                                            println!("  Responding to GetStats with dummy data");
                                            create_success_response(b"dummy_stats_data")
                                        }
                                        _ => {
                                            // Unknown command: error response
                                            println!("  Responding to unknown command with error");
                                            create_error_response(1) // InvalidCommand
                                        }
                                    };

                                    if let Err(e) = socket.write_all(&response).await {
                                        println!("Failed to send response: {}", e);
                                        break;
                                    }

                                    if let Err(e) = socket.flush().await {
                                        println!("Failed to flush response: {}", e);
                                        break;
                                    }

                                    println!("  Sent response: {} bytes", response.len());
                                }
                            }
                            Err(e) => {
                                println!("Dummy server read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
        });

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_request_response_dissection() -> io::Result<()> {
        let client_ip = "127.0.0.1";
        let client_port = 8091;

        println!("\n=== Testing Ping Request/Response ===");
        println!("Starting test for {}:{}", client_ip, client_port);

        let capture = TsharkCapture::new(client_ip, client_port)?;
        let mut tshark = capture.start()?;

        sleep(Duration::from_millis(1000)).await;

        // Start server
        run_dummy_server(client_ip, client_port).await?;
        sleep(Duration::from_millis(500)).await;

        // Connect and send request
        let mut stream = match TcpStream::connect(format!("{}:{}", client_ip, client_port)).await {
            Ok(stream) => {
                println!("Connected to server");
                stream
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                let _ = tshark.kill();
                return Err(e);
            }
        };

        // Send Ping request
        let ping_command = ServerCommand::Ping(Ping::default());
        let request_packet = create_request_packet(&ping_command);

        println!("Sending Ping request: {} bytes", request_packet.len());
        if let Err(e) = stream.write_all(&request_packet).await {
            let _ = tshark.kill();
            return Err(e);
        }
        stream.flush().await?;

        // Wait for response (server will send it automatically)
        sleep(Duration::from_millis(500)).await;

        // Wait for capture
        sleep(Duration::from_secs(2)).await;

        // Stop tshark
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        // Analyze results
        let packets = capture.analyze()?;

        if packets.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "No packets captured"));
        }

        // Find Iggy packets
        let iggy_packets: Vec<&Value> = packets
            .iter()
            .filter(|p| p["_source"]["layers"].get("iggy").is_some())
            .collect();

        if iggy_packets.is_empty() {
            for packet in &packets {
                if let Some(layers) = packet["_source"]["layers"].as_object() {
                    println!("Available layers:");
                    for key in layers.keys() {
                        println!("  - {}", key);
                    }
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No Iggy packets found in capture",
            ));
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        // Verify request packet
        let mut found_request = false;
        let mut found_response = false;

        for (idx, iggy_packet) in iggy_packets.iter().enumerate() {
            let iggy = &iggy_packet["_source"]["layers"]["iggy"];
            println!("\nPacket {}: {:?}", idx, iggy);

            // Check if it's a request
            if let Some(command) = iggy.get("iggy.request.command") {
                println!("  -> Request packet found");
                found_request = true;

                // Verify command code
                if let Some(cmd_val) = command.as_str() {
                    assert_eq!(cmd_val, "1", "Expected command 1 (Ping), got {}", cmd_val);
                }

                // Verify command name
                if let Some(cmd_name) = iggy.get("iggy.request.command_name").and_then(|v| v.as_str()) {
                    assert_eq!(cmd_name, "Ping", "Expected command name 'Ping', got {}", cmd_name);
                }

                // Verify length
                if let Some(length) = iggy.get("iggy.request.length").and_then(|v| v.as_str()) {
                    assert_eq!(length, "4", "Expected length 4, got {}", length);
                }
            }

            // Check if it's a response
            if let Some(status) = iggy.get("iggy.response.status") {
                println!("  -> Response packet found");
                found_response = true;

                // Verify status code
                if let Some(status_val) = status.as_str() {
                    assert_eq!(status_val, "0", "Expected status 0 (OK), got {}", status_val);
                }

                // Verify status name
                if let Some(status_name) = iggy.get("iggy.response.status_name").and_then(|v| v.as_str()) {
                    assert_eq!(status_name, "OK", "Expected status name 'OK', got {}", status_name);
                }

                // Verify length (should be 0 for Ping response)
                if let Some(length) = iggy.get("iggy.response.length").and_then(|v| v.as_str()) {
                    assert_eq!(length, "0", "Expected response length 0, got {}", length);
                }
            }
        }

        assert!(found_request, "Request packet not found in capture");
        assert!(found_response, "Response packet not found in capture");

        println!("\n✓ Ping request/response dissection verified");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_stats_dissection() -> io::Result<()> {
        let client_ip = "127.0.0.1";
        let client_port = 8092;

        println!("\n=== Testing GetStats Command ===");
        println!("Starting test for {}:{}", client_ip, client_port);

        let capture = TsharkCapture::new(client_ip, client_port)?;
        let mut tshark = capture.start()?;

        sleep(Duration::from_millis(1000)).await;

        // Start server
        run_dummy_server(client_ip, client_port).await?;
        sleep(Duration::from_millis(500)).await;

        // Connect
        let mut stream = match TcpStream::connect(format!("{}:{}", client_ip, client_port)).await {
            Ok(stream) => {
                println!("Connected to server");
                stream
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                let _ = tshark.kill();
                return Err(e);
            }
        };

        // Send GetStats request (command code 10)
        // Manually create the packet for GetStats
        let mut request = BytesMut::new();
        request.put_u32_le(4); // LENGTH (only command code, no payload)
        request.put_u32_le(10); // COMMAND_CODE (GetStats)
        let request_packet = request.to_vec();

        println!("Sending GetStats request: {} bytes", request_packet.len());
        if let Err(e) = stream.write_all(&request_packet).await {
            let _ = tshark.kill();
            return Err(e);
        }
        stream.flush().await?;

        // Wait for response
        sleep(Duration::from_millis(500)).await;

        // Wait for capture
        sleep(Duration::from_secs(2)).await;

        // Stop tshark
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        // Analyze results
        let packets = capture.analyze()?;

        if packets.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "No packets captured"));
        }

        // Find Iggy packets
        let iggy_packets: Vec<&Value> = packets
            .iter()
            .filter(|p| p["_source"]["layers"].get("iggy").is_some())
            .collect();

        if iggy_packets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No Iggy packets found in capture",
            ));
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        let mut found_request = false;
        let mut found_response = false;

        for (idx, iggy_packet) in iggy_packets.iter().enumerate() {
            let iggy = &iggy_packet["_source"]["layers"]["iggy"];
            println!("\nPacket {}: {:?}", idx, iggy);

            // Check request
            if let Some(command) = iggy.get("iggy.request.command") {
                println!("  -> Request packet found");
                found_request = true;

                if let Some(cmd_val) = command.as_str() {
                    assert_eq!(cmd_val, "10", "Expected command 10 (GetStats), got {}", cmd_val);
                }

                if let Some(cmd_name) = iggy.get("iggy.request.command_name").and_then(|v| v.as_str()) {
                    assert_eq!(cmd_name, "GetStats", "Expected command name 'GetStats', got {}", cmd_name);
                }
            }

            // Check response
            if let Some(status) = iggy.get("iggy.response.status") {
                println!("  -> Response packet found");
                found_response = true;

                if let Some(status_val) = status.as_str() {
                    assert_eq!(status_val, "0", "Expected status 0 (OK), got {}", status_val);
                }

                // This response should have payload (dummy_stats_data)
                if let Some(length) = iggy.get("iggy.response.length").and_then(|v| v.as_str()) {
                    let length_val: u32 = length.parse().unwrap_or(0);
                    assert!(length_val > 0, "Expected response with payload, got length {}", length);
                }
            }
        }

        assert!(found_request, "GetStats request packet not found");
        assert!(found_response, "GetStats response packet not found");

        println!("\n✓ GetStats request/response dissection verified");
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_error_response_dissection() -> io::Result<()> {
        let client_ip = "127.0.0.1";
        let client_port = 8093;

        println!("\n=== Testing Error Response ===");
        println!("Starting test for {}:{}", client_ip, client_port);

        let capture = TsharkCapture::new(client_ip, client_port)?;
        let mut tshark = capture.start()?;

        sleep(Duration::from_millis(1000)).await;

        // Start server
        run_dummy_server(client_ip, client_port).await?;
        sleep(Duration::from_millis(500)).await;

        // Connect
        let mut stream = match TcpStream::connect(format!("{}:{}", client_ip, client_port)).await {
            Ok(stream) => {
                println!("Connected to server");
                stream
            }
            Err(e) => {
                println!("Failed to connect: {}", e);
                let _ = tshark.kill();
                return Err(e);
            }
        };

        // Send unknown command (will trigger error response)
        let mut request = BytesMut::new();
        request.put_u32_le(4); // LENGTH
        request.put_u32_le(999); // Unknown COMMAND_CODE
        let request_packet = request.to_vec();

        println!("Sending unknown command: {} bytes", request_packet.len());
        if let Err(e) = stream.write_all(&request_packet).await {
            let _ = tshark.kill();
            return Err(e);
        }
        stream.flush().await?;

        // Wait for response
        sleep(Duration::from_millis(500)).await;

        // Wait for capture
        sleep(Duration::from_secs(2)).await;

        // Stop tshark
        let _ = tshark.kill();
        sleep(Duration::from_millis(500)).await;

        // Analyze results
        let packets = capture.analyze()?;

        if packets.is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "No packets captured"));
        }

        // Find Iggy packets
        let iggy_packets: Vec<&Value> = packets
            .iter()
            .filter(|p| p["_source"]["layers"].get("iggy").is_some())
            .collect();

        if iggy_packets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No Iggy packets found in capture",
            ));
        }

        println!("Found {} Iggy packet(s)", iggy_packets.len());

        let mut found_error_response = false;

        for (idx, iggy_packet) in iggy_packets.iter().enumerate() {
            let iggy = &iggy_packet["_source"]["layers"]["iggy"];
            println!("\nPacket {}: {:?}", idx, iggy);

            // Check for error response
            if let Some(status) = iggy.get("iggy.response.status") {
                if let Some(status_val) = status.as_str() {
                    if status_val != "0" {
                        println!("  -> Error response found");
                        found_error_response = true;

                        assert_eq!(status_val, "1", "Expected status 1 (InvalidCommand), got {}", status_val);

                        // Verify status name
                        if let Some(status_name) = iggy.get("iggy.response.status_name").and_then(|v| v.as_str()) {
                            assert_eq!(status_name, "InvalidCommand", "Expected 'InvalidCommand', got {}", status_name);
                        }

                        // Verify length is 0 for error response
                        if let Some(length) = iggy.get("iggy.response.length").and_then(|v| v.as_str()) {
                            assert_eq!(length, "0", "Expected error response length 0, got {}", length);
                        }
                    }
                }
            }
        }

        assert!(found_error_response, "Error response packet not found");

        println!("\n✓ Error response dissection verified");
        Ok(())
    }
}
