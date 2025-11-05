### 목표
Custom Wireshark Dissector(Lua 기반)를 만들어 iggy 프로토콜의 **바이너리 통신(TCP/QUIC)** 데이터를 분석 가능하게 한다. HTTP(JSON)는 제외한다.

단, 초기 구현이므로 확장성을 고려하되 ping, payload를 가지는 요청 프로토콜 하나, 응답 프로토콜(0(성공), 에러 하나)만 구현된 lua 스크립트를 작성한다.

해당 프로토콜만 테스트하는 rust 코드를 작성한다.

코드는 프로젝트 루트 경로 하위에 protocol-dissector 디렉토리를 만들고, iggy 프로젝트의 하위 프로젝트로 추가하여, 필요한 의존성만 받도록 한다. 
테스트코드를 작성할 때, 바이너리 데이터를 실제 iggy 서버의 로직을 사용하여 변경에 유현하게 대응하기 위함이다. 

***

### 전반적 요구사항

- iggy 프로토콜의 TCP 및 QUIC 통신은 바이너리 형식으로 이루어짐.
- 바이너리 데이터의 형식을 코드를 통해 분석하고, Wireshark에서 사람이 읽기 쉽게 파싱하도록 함.
- 프로토콜 포맷만 준수한다면, 데이터 전송 방식 자체는 제한하지 않음.
- Request와 Response를 각각 별도로 구현해야 함.

***

### 개발 방향

- **언어:** Lua
    - Wireshark에서 Lua 기반 dissector 지원이 풍부하고 문법이 단순함.
- **자동화:** Wireshark의 경량 CLI `tshark`를 호출해 테스트를 자동화.
- **분석 대상 코드:**
    - Request 코드/이름: `core/common/src/types/command/mod.rs`
    - 바이너리 명세 관리: `core/server/src/binary/command.rs`
    - 각 프로토콜 struct는 `BytesSerializable` 트레이트를 구현함.  
      이 구현을 분석하여 실제 바이트 구조를 파악.

***

### 공통 데이터 타입 처리

- 공통 데이터 타입에 대한 개별 파서를 만들어 재사용.  
  Wireshark에서도 해당 타입을 식별 가능해야 함.
- 코드로부터 확인할 주요 공통 타입 예시:  
  Consumer, Identifier, PolledMessages, Message, ConsumerOffsetInfo  
  (단, 오래된 문서 기준이므로 실제 구현을 코드로 검증해야 함.)
- 공통 처리 기준:  
  `BytesSerializable`을 구현하고, 여러 프로토콜에서 재사용되는 경우 공통 타입으로 간주한다.

***

### 프로토콜 스키마

#### Request

| 필드 | 크기 | 설명 |
|------|------|------|
| length | 4 bytes (u32) | 전체 길이 = code(4) + payload(N) |
| code | 4 bytes (u32) | 요청 코드 |
| payload | N bytes | 실제 데이터 |

**예시:** payload가 100 bytes라면  
length는 104 (code + payload)  
총 메시지 크기는 108 bytes (length + code + payload)

#### Response

| 필드 | 크기 | 설명 |
|------|------|------|
| status | 4 bytes (u32) | 상태 코드 (0: 성공, 그 외: 오류) |
| length | 4 bytes (u32) | 전체 길이 = status(4) + payload(N) |
| payload | N bytes | 응답 데이터 (성공 시에만 존재) |

**에러 처리 규칙:**
- `status`가 에러일 경우: length는 0, payload는 비어 있음.
- 존재하지 않는 리소스 요청 시: status 0이지만 payload 비어 있음.

***

### 에러 코드

- 중앙 관리 위치: `core/common/src/error/iggy_error.rs`
- HTTP 전송용 변환: `core/server/src/http/error.rs`  
  (Dissector에는 직접 필요 없지만 문맥 참고용)

----

### 초기 구현 시 주의사항

- **TCP 세그먼트 재조립은 당장 고려하지 않음.**
    - 단순 데모용 구현 후 피드백을 받는 단계.
    - 나중에 추가 시 Length 필드 기반으로 전체 메시지 크기를 계산하고,  
      Wireshark의 `desegment_len` 값을 통해 구현.
- **필드 및 관련 로직의 변경 용이성 확보.**
    - 구조별, 역할별 Lua 스크립트 분리 및 모듈화.
        - 요청 code 별로 payload 처리하는 함수 포인터, 필드 정의, 이름 등을 묶어서 관리해야 한다.
        - lua의 테이블을 사용하여 묶어서 관리한다.

### 테스트 코드

다음과 같은 예시를 참고한다.

```rust 
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
            .join("iggy_simple.lua")
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
    println!("  Hex: {}", hex::encode(&ping_packet));

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
```
