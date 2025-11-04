Custom Wireshark Dissector 만들기.

iggy 프로토콜 중에서 HTTP(json)을 제외한 TCP/QUIC는 바이너리 프로토콜을 사용하며, 이 데이터를 분석하기 쉽도록 해야 한다.

프로토콜 포맷을 지킨다면 바이너리 프로토콜을 보내는 방법은 신경쓰지 않는다.

다음 문서를 참고할 수 있으나, 현제 코드와 일치하지 않는 문제가 있다.

https://iggy.apache.org/docs/server/schema/

코드를 분석하여 올바른 프로토콜 형식을 구해야 한다.

Custom Wireshark Dissector 플러그인의 언어는 lua를 사용한다. 자료가 많고 문법이 쉽기 때문이다.

Wireshark에서 제공하는 경랑 CLI 버전인 tshark를 호출하도록 해서 테스트까지 자동화하도록 한다.

기본적으로는 이런 구조에, Request code와 이름은 `core/common/src/types/command/mod.rs` 에서 확인 가능하다.

바이너리 프로토콜은 모두 `core/server/src/binary/command.rs` 에서 중앙 관리하는데,
각 프로토콜 struct는 BytesSerializable을 구한현다. 이 구현을 분석하여 가지는 바이트 값을 알아낼 수 있다.
(이 동작은 AI에게 맞기고 테스트코드 작성 후 내가 확인하는 식으로 하면 될 듯.)

또, 공통 데이터 타입들이 존재하는데, 이것들에 대한 파서는 따로 만들어서 재사용하가. + WireShark에서도 이게 특정 공통 데이터 타입인걸 파악 가능하게 하기.
- 웹 docs에서는 Consumer, Identifier, PolledMessages, Message, ConsumerOffsetInfo 라는데, 또 바뀌었을 수도 있음.
- 코드 확인하기


플러그인 두는 위치는 내 컴퓨터 기준 `~/.local/lib/wireshark/plugins/`임.

구현 시 주의사항
1. TCP 세그먼트 재조립 고려. Length 필드를 읽어 전체 메시지 크기 파악. Wireshark의 `desegment_len`(추가로 필요한 바이트 수)를 참고해서 구현 가능하다고 함.

TODO
일단 가장 간단한 PING이나 USER LOGIN 같은 쉽게 테스트 가능하고 검사되는걸로 만들기. 테스트 코드 등 전체적인 틀을 짜기.
대충 몇개 더 만들면서 재사용이나 전체적인 틀이 잘 작용되도록 개선하기 -> PR 날리기
나머지 구현들은 피드백 받고 천천히 만들기


```
Request schema
All the requests are represented as a binary message. The message consists of 3 parts: length, code and payload:

length - 4-byte integer (u32) which represents the total length: code (4 bytes) + payload (N bytes)
code - 4-byte integer (u32) which represents the request code
payload - binary data of N bytes length
For example, if the payload is 100 bytes, the length will have a value of 104 (100 bytes for payload + 4 const bytes for the code). The message as whole will have 108 (4 + 4 + 100) bytes size.

+-----------------------------------------------------------+
|           |           |                                   |
|  LENGTH   |   CODE    |              PAYLOAD              |
|           |           |                                   |
+-----------------------------------------------------------+
|  4 bytes  |  4 bytes  |              N bytes              |

Response schema
All the responses are represented as a binary message. The message consists of 3 parts: status, length and payload:

status - 4-byte integer (u32) which represents the status code. The status code is 0 for success and any other value for an error.
length - 4-byte integer (u32) which represents the total length: status (4 bytes) + payload (N bytes)
payload - binary data of N bytes length
In case of errors, the length will be always equal to 0 and the payload will be empty.

When trying to fetch the resource which may not exist, such as a stream, topic, user etc., the response will have a status code 0 (OK), but the payload will be empty, as there's no data to return.

+-----------------------------------------------------------+
|           |           |                                   |
|  STATUS   |  LENGTH   |              PAYLOAD              |
|           |           |                                   |
+-----------------------------------------------------------+
|  4 bytes  |  4 bytes  |              N bytes              |
```


그리고 약간 테스트코드는 내가 익숙한 방식대로 요청해서 AI가 짜준건데, 괜찮으려나. 근데 이런 방식이 익숙하긴 함. iggy 나 rust 프로젝트 타입에 맞는진 모르겠어서 나중에 수정하긴 해야겠지만.

```rust
// tests/dissector_validation.rs

use std::process::{Command, Stdio, Child};
use std::io::{BufReader, BufRead};
use bytes::Bytes;
use serde_json::Value;

struct LiveDissectorTest {
tshark_process: Child,
server: TestServer,
client: TcpClient,
}

impl LiveDissectorTest {
async fn new() -> Self {
let port = 8090;

          // 1. tshark를 live capture 모드로 시작
          let tshark = Command::new("tshark")
              .args([
                  "-i", "lo0",  // 실시간 캡처
                  "-f", &format!("tcp port {}", port),  // BPF 필터
                  "-Y", "iggy",  // Wireshark display 필터
                  "-T", "json",  // JSON 출력
                  "-l",  // Line buffered (실시간 출력)
              ])
              .stdout(Stdio::piped())
              .stderr(Stdio::null())
              .spawn()
              .expect("tshark 시작 실패");

          tokio::time::sleep(Duration::from_millis(500)).await;

          // 2. 테스트 서버 시작
          let server = start_test_server(port).await;

          // 3. 클라이언트 연결
          let client = TcpClient::new(&format!("127.0.0.1:{}", port))
              .await
              .unwrap();

          Self {
              tshark_process: tshark,
              server,
              client,
          }
      }

      // 핵심: 명령어 전송 + dissection 결과 비교
      async fn test_command<T>(&mut self, command: &T) -> anyhow::Result<()>
      where
          T: Command + BytesSerializable
      {
          // 1. Rust 구현체로 바이너리 생성
          let expected_bytes = command.to_bytes();
          let expected_code = command.code();

          // 2. 실제 명령어 전송 (클라이언트를 통해)
          self.send_command_via_client(command).await?;

          // 3. tshark 출력 읽기 (실시간)
          let dissection = self.read_next_packet()?;

          // 4. 비교
          self.verify_dissection(&dissection, expected_code, &expected_bytes)?;

          Ok(())
      }

      fn read_next_packet(&mut self) -> anyhow::Result<Value> {
          let stdout = self.tshark_process.stdout.as_mut().unwrap();
          let mut reader = BufReader::new(stdout);
          let mut line = String::new();

          // JSON 한 줄 읽기 (tshark -T json은 줄마다 패킷 하나)
          reader.read_line(&mut line)?;

          let packet: Value = serde_json::from_str(&line)?;
          Ok(packet)
      }

      fn verify_dissection(
          &self,
          dissection: &Value,
          expected_code: u32,
          expected_bytes: &Bytes,
      ) -> anyhow::Result<()> {
          let layers = &dissection["_source"]["layers"];

          // 1. Command code 검증
          let actual_code: u32 = layers["iggy.command.code"][0]
              .as_str()
              .unwrap()
              .parse()?;
          assert_eq!(actual_code, expected_code, "Command code 불일치");

          // 2. 원시 바이트와 dissection 결과 비교
          // tshark가 파싱한 필드들을 다시 조합해서 원본과 일치하는지 확인
          let reconstructed = self.reconstruct_bytes_from_dissection(dissection)?;
          assert_eq!(&reconstructed, expected_bytes,
              "Dissection 결과로 재구성한 바이트가 원본과 다름");

          Ok(())
      }

      fn reconstruct_bytes_from_dissection(&self, dissection: &Value) ->
anyhow::Result<Bytes> {
// tshark dissection 결과에서 hex dump를 추출하거나
// 개별 필드들을 다시 조합
let layers = &dissection["_source"]["layers"];

          // iggy 레이어의 raw hex data
          let hex_data = layers["iggy.data"]
              .as_str()
              .ok_or_else(|| anyhow::anyhow!("iggy.data not found"))?;

          // hex string을 bytes로 변환
          let bytes = hex::decode(hex_data.replace(":", ""))?;
          Ok(Bytes::from(bytes))
      }
}

모든 명령어 자동 테스트

#[tokio::test]
async fn test_all_commands_dissection() {
let mut test = LiveDissectorTest::new().await;

      // ServerCommand의 모든 variant를 테스트
      test_all_command_variants(&mut test).await;

      test.shutdown().await;
}

async fn test_all_command_variants(test: &mut LiveDissectorTest) {
// 각 명령어별로 테스트 케이스 생성

      // 1. Ping
      let ping = Ping::default();
      test.test_command(&ping).await.unwrap();

      // 2. GetStats
      let get_stats = GetStats::default();
      test.test_command(&get_stats).await.unwrap();

      // 3. LoginUser
      let login = LoginUser {
          username: "testuser".into(),
          password: "testpass".into(),
      };
      test.test_command(&login).await.unwrap();

      // 4. CreateStream
      let create_stream = CreateStream {
          stream_id: Some(1),
          name: "test-stream".into(),
      };
      test.test_command(&create_stream).await.unwrap();

      // 5. SendMessages (복잡한 케이스)
      let send_messages = SendMessages {
          metadata_length: calculate_metadata_length(...),
          stream_id: Identifier::numeric(1).unwrap(),
          topic_id: Identifier::numeric(1).unwrap(),
          partitioning: Partitioning::balanced(),
          batch: create_test_messages(3), // 3개 메시지
      };
      test.test_command(&send_messages).await.unwrap();

      // ... 나머지 모든 명령어
}

더 정교한 비교: 필드별 검증

impl LiveDissectorTest {
fn verify_dissection_detailed(
&self,
dissection: &Value,
command: &impl Command,
) -> anyhow::Result<()> {
let layers = &dissection["_source"]["layers"];

          // Command 타입에 따라 다르게 검증
          match command.code() {
              PING_CODE => {
                  // Ping은 payload 없음
                  assert!(layers.get("iggy.payload").is_none());
              },
              SEND_MESSAGES_CODE => {
                  let cmd = command.downcast_ref::<SendMessages>().unwrap();

                  // 각 필드 검증
                  assert_eq!(
                      layers["iggy.stream_id"][0].as_str().unwrap(),
                      cmd.stream_id.to_string()
                  );
                  assert_eq!(
                      layers["iggy.topic_id"][0].as_str().unwrap(),
                      cmd.topic_id.to_string()
                  );
                  assert_eq!(

layers["iggy.messages_count"][0].as_str().unwrap().parse::<u32>()?,
cmd.batch.count()
);

                  // Partitioning 검증
                  let expected_kind = cmd.partitioning.kind as u8;
                  let actual_kind = layers["iggy.partitioning.kind"][0]
                      .as_str()
                      .unwrap()
                      .parse::<u8>()?;
                  assert_eq!(actual_kind, expected_kind);

                  // 개별 메시지 검증
                  for (i, msg) in cmd.batch.iter().enumerate() {
                      let field_name = format!("iggy.message[{}].payload", i);
                      let dissected_payload = layers[&field_name][0].as_str().unwrap();
                      let expected_payload = hex::encode(&msg.payload);
                      assert_eq!(dissected_payload, expected_payload);
                  }
              },
              // ... 다른 명령어들
              _ => {}
          }

          Ok(())
      }
}

매크로로 모든 명령어 자동 생성

macro_rules! test_all_commands {
(
$(
$variant:ident($type:ty) => $factory:expr
),* $(,)?
) => {
#[tokio::test]
async fn test_all_server_commands() {
let mut test = LiveDissectorTest::new().await;

              $(
                  {
                      println!("Testing {}", stringify!($variant));
                      let command: $type = $factory;
                      test.test_command(&command)
                          .await
                          .expect(&format!("{} 테스트 실패", stringify!($variant)));
                  }
              )*

              test.shutdown().await;
          }
      };
}

// 사용
test_all_commands! {
Ping(Ping) => Ping::default(),
GetStats(GetStats) => GetStats::default(),
GetMe(GetMe) => GetMe::default(),

      LoginUser(LoginUser) => LoginUser {
          username: "test".into(),
          password: "test".into(),
      },

      CreateStream(CreateStream) => CreateStream {
          stream_id: Some(1),
          name: "test-stream".into(),
      },

      SendMessages(SendMessages) => {
          let messages = vec![
              IggyMessage::new(None, b"msg1".to_vec(), None),
              IggyMessage::new(None, b"msg2".to_vec(), None),
          ];
          SendMessages::new(
              Identifier::numeric(1).unwrap(),
              Identifier::numeric(1).unwrap(),
              Partitioning::balanced(),
              messages,
          )
      },

      // ... 나머지 47개 모든 명령어
}

실행 흐름

// 실제 통합 테스트
#[tokio::test]
async fn integration_test_dissector() {
// 1. tshark live capture 시작
let mut test = LiveDissectorTest::new().await;

      // 2. 서버 준비 대기
      tokio::time::sleep(Duration::from_secs(1)).await;

      // 3. 각 명령어를 순차적으로 전송 + 검증
      for (name, factory) in get_all_test_commands() {
          println!("Testing command: {}", name);

          let command = factory();
          let expected_bytes = command.to_bytes();

          // 전송
          send_raw_command(&mut test.client, &command).await.unwrap();

          // tshark 결과 읽기
          let dissection = test.read_next_packet().unwrap();

          // 비교
          verify_exact_match(&dissection, &expected_bytes).unwrap();

          println!("✓ {} passed", name);
      }

      test.shutdown().await;
      println!("\n모든 {} 개 명령어 테스트 통과!", 47);
}

fn verify_exact_match(dissection: &Value, expected_bytes: &Bytes) ->
anyhow::Result<()> {
// tshark가 파싱한 raw data 추출
let actual_hex = dissection["_source"]["layers"]["iggy"]["iggy.data"]
.as_str()
.unwrap();

      let actual_bytes = hex::decode(actual_hex)?;

      assert_eq!(
          actual_bytes.as_slice(),
          expected_bytes.as_ref(),
          "Dissection 결과와 to_bytes() 결과가 다름!\n\
           Expected: {:02x?}\n\
           Actual:   {:02x?}",
          expected_bytes,
          actual_bytes
      );

      Ok(())
}
```
