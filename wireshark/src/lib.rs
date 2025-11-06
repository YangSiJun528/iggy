#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use iggy_common::ping::Ping;
    use server::binary::command::ServerCommand;
    use serde_json::Value;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::{Child, Command as ProcessCommand, Stdio};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    fn create_packet_from_server_command(command: &ServerCommand) -> Vec<u8> {
        let bytes = command.to_bytes();
        let mut buf = BytesMut::with_capacity(4 + bytes.len());
        buf.put_u32_le(bytes.len() as u32);
        buf.put_slice(&bytes);
        buf.to_vec()
    }

    struct TsharkCapture {
        ip: String,
        port: u16,
        pcap_file: PathBuf,
    }

    impl TsharkCapture {
        fn new(ip: &str, port: u16) -> io::Result<Self> {
            let file = format!("/tmp/iggy_test_{}.pcap", port);
            Ok(Self {
                ip: ip.to_string(),
                port,
                pcap_file: PathBuf::from(file),
            })
        }

        fn start(&self) -> io::Result<Child> {
            ProcessCommand::new("tshark")
                .args([
                    "-i",
                    "lo0",
                    "-w",
                    self.pcap_file.to_str().unwrap(),
                    "-f",
                    &format!("tcp and host {} and port {}", self.ip, self.port),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }

        fn analyze(&self) -> io::Result<Vec<Value>> {
            let dissector = std::env::current_dir()?.join("iggy_dissector.lua");
            let output = ProcessCommand::new("tshark")
                .args([
                    "-r",
                    self.pcap_file.to_str().unwrap(),
                    "-Y",
                    "iggy",
                    "-T",
                    "json",
                    "-X",
                    &format!("lua_script:{}", dissector.display()),
                ])
                .output()?;

            if !output.status.success() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("tshark failed: {:?}", output.status),
                ));
            }

            let json_str = String::from_utf8_lossy(&output.stdout);
            let packets: Vec<Value> =
                serde_json::from_str(&json_str).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            Ok(packets)
        }
    }

    impl Drop for TsharkCapture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.pcap_file);
        }
    }

    async fn run_dummy_server(ip: &str, port: u16) -> io::Result<()> {
        let listener = TcpListener::bind(format!("{}:{}", ip, port)).await?;
        loop {
            let (mut socket, _) = listener.accept().await?;
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match socket.try_read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            sleep(Duration::from_millis(10)).await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_ping_dissection_with_tshark() -> io::Result<()> {
        let ip = "127.0.0.1";
        let port = 8091;
        let capture = TsharkCapture::new(ip, port)?;
        let mut tshark = capture.start()?;

        tokio::spawn(run_dummy_server(ip, port));
        sleep(Duration::from_millis(800)).await;

        let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
        let ping_command = ServerCommand::Ping(Ping::default());
        let packet = create_packet_from_server_command(&ping_command);

        stream.write_all(&packet).await?;
        stream.flush().await?;

        sleep(Duration::from_secs(1)).await;
        let _ = tshark.kill();
        sleep(Duration::from_millis(300)).await;

        let packets = capture.analyze()?;
        assert!(
            !packets.is_empty(),
            "no packets captured for ip={}, port={}",
            ip,
            port
        );

        let iggy_packet = packets
            .iter()
            .find(|p| p["_source"]["layers"].get("iggy").is_some())
            .expect("no Iggy packet found");

        let iggy = &iggy_packet["_source"]["layers"]["iggy"];
        assert_eq!(
            iggy["iggy.message_type"].as_str().unwrap(),
            "Request",
            "expected Request"
        );
        assert_eq!(
            iggy["iggy.request.code_name"].as_str().unwrap(),
            "Ping",
            "expected Ping"
        );
        println!("✓ Ping dissection verified for {}:{}", ip, port);
        Ok(())
    }
}
