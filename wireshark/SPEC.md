# Iggy Binary Protocol - Wireshark Dissector 구현 가이드

이 문서는 iggy 프로토콜의 Wireshark Dissector(Lua)를 구현하기 위한 가이드입니다.
전체 payload 구조를 상세히 담는 대신, **어떤 코드를 참고해야 하는지**와 **주의사항**에 집중합니다.

---

## 1. 프로토콜 기본 구조

### 1.1 요청(Request) 포맷

```
+--------+--------+----------+
| length | code   | payload  |
+--------+--------+----------+
| 4B     | 4B     | N bytes  |
| u32    | u32    | variable |
+--------+--------+----------+
```

- **length**: code(4B) + payload(N) 길이 *(length 필드 자체는 제외)*
- **code**: 요청 코드 (u32, little-endian)
- **payload**: 실제 데이터 (command마다 다름)

**참고 코드:** `core/server/src/binary/command.rs:151-157`

### 1.2 응답(Response) 포맷

```
+--------+--------+----------+
| status | length | payload  |
+--------+--------+----------+
| 4B     | 4B     | N bytes  |
| u32    | u32    | variable |
+--------+--------+----------+
```

- **status**: 0=성공, 그 외=에러 코드 (u32, little-endian)
- **length**: payload 길이만 (status는 제외)
- **payload**: 응답 데이터 (에러 시 비어있음)

**참고 코드:** `core/server/src/tcp/sender.rs:78-98`

---

## 2. Command 코드 목록

총 50개의 command가 있으며, 모두 `core/common/src/types/command/mod.rs`에 정의되어 있습니다.

### 주요 Command 그룹

| 범위 | 카테고리 | 예시 |
|------|----------|------|
| 1-19 | System | PING(1), GET_STATS(10) |
| 20-44 | User & Client | LOGIN_USER(38), GET_ME(20) |
| 100-122 | Message | POLL_MESSAGES(100), SEND_MESSAGES(101) |
| 200-205 | Stream | GET_STREAM(200), CREATE_STREAM(202) |
| 300-305 | Topic | GET_TOPIC(300), CREATE_TOPIC(302) |
| 402-503 | Partition & Segment | CREATE_PARTITIONS(402) |
| 600-605 | Consumer Group | GET_CONSUMER_GROUP(600) |

**전체 목록:** `core/common/src/types/command/mod.rs:28-121`

---

## 3. 구현 가이드

### 3.1 요청 Payload 파싱

**요청은 `BytesSerializable` trait를 사용합니다.**

#### 구현 절차
1. Command 코드로 어떤 요청인지 식별
2. 해당 command 구현 찾기: `core/common/src/commands/**/*.rs`
3. `BytesSerializable::from_bytes()` 또는 `to_bytes()` 구현 참고
4. 바이트 순서대로 필드 파싱

#### 예시: Ping (Code: 1) - 가장 단순
- **Payload**: 비어있음
- **코드**: `core/common/src/commands/system/ping.rs`

#### 예시: GetStream (Code: 200) - 단순
- **Payload**: Identifier 하나
- **코드**: `core/common/src/commands/streams/get_stream.rs:50-63`

#### 예시: LoginUser (Code: 38) - 중간
- **Payload**: username(가변) + password(가변) + version(가변, optional) + context(가변, optional)
- **코드**: `core/common/src/commands/users/login_user.rs:82-110`

#### 예시: PollMessages (Code: 100) - 복잡
- **Payload**: Consumer + stream_id + topic_id + partition_id + strategy + count + auto_commit
- **코드**: `core/common/src/commands/messages/poll_messages.rs:138-206`

### 3.2 요청과 응답 매핑 ⚠️ 핵심!

**응답 헤더에는 command code가 없습니다!**

응답 포맷(`status + length + payload`)에는 어떤 요청에 대한 응답인지 식별할 수 있는 코드가 없습니다.
그럼 클라이언트는 어떻게 올바른 mapper 함수를 호출할까요?

#### 요청-응답 매핑 원리

**IGGY는 병렬 요청을 지원하지 않습니다!**

클라이언트는 Mutex lock을 사용하여 **순차적으로만** 요청/응답을 처리합니다.
따라서 응답은 항상 마지막으로 보낸 요청에 대한 것임이 보장됩니다.

```rust
// core/sdk/src/tcp/tcp_client.rs:485-550 (핵심 로직 요약)
async fn send_raw(&self, code: u32, payload: Bytes) -> Result<Bytes, IggyError> {
    let stream = self.stream.clone();  // Arc<Mutex<TcpStream>>
    tokio::spawn(async move {
        let mut stream = stream.lock().await;  // 1. Lock 획득 (다른 요청 차단)

        // 2. 요청 전송
        stream.write(&length.to_le_bytes()).await?;
        stream.write(&code.to_le_bytes()).await?;
        stream.write(&payload).await?;

        // 3. Lock을 유지한 채로 응답 대기 (다른 요청은 여전히 대기 중)
        let mut response_buffer = [0u8; 8];
        stream.read(&mut response_buffer).await?;

        // 4. 응답 파싱 완료
        return handle_response(status, length, stream).await;
        // 5. 함수 종료 시 lock 해제 → 다음 요청 가능
    }).await?
}
```

**시나리오 예시**:
```
시간축 →

Thread A: [Lock 획득] → [요청1 전송] → [응답1 대기...] → [응답1 수신] → [Lock 해제]
                                         ↑
Thread B:           [Lock 대기................] → [Lock 획득] → [요청2 전송] →
```

**중요**: Kafka 같은 시스템은 correlation ID로 비순차 응답을 지원하지만, **IGGY는 순차 처리만 지원**합니다.
- ✅ 장점: 구현 단순, 응답 매칭 명확 (correlation ID 불필요)
- ❌ 단점: 처리량 제한 (파이프라이닝 없음), 한 요청이 느리면 모든 후속 요청 대기

```rust
// core/binary_protocol/src/client/binary_users/mod.rs:132-144
async fn login_user(&self, username: &str, password: &str) -> Result<IdentityInfo, IggyError> {
    let response = self
        .send_with_response(&LoginUser {  // ← LoginUser 요청 전송
            username: username.to_string(),
            password: password.to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            context: Some("".to_string()),
        })
        .await?;
    mapper::map_identity_info(response)  // ← map_identity_info()로 응답 파싱
}
```

#### 요청 Command → 응답 Mapper 매핑표

| 요청 Command | Code | 응답 Mapper 함수 | 파일 위치 (client) |
|-------------|------|----------------|------------------|
| LoginUser | 38 | `map_identity_info()` | `binary_users/mod.rs:143` |
| GetStats | 10 | `map_stats()` | `binary_system/mod.rs:37` |
| GetStream | 200 | `map_stream()` | `binary_streams/mod.rs:43` |
| CreateStream | 202 | `map_stream()` | `binary_streams/mod.rs:64` |
| GetMe | 20 | `map_client()` | `binary_system/mod.rs:43` |
| GetClient | 21 | `map_client()` | `binary_system/mod.rs:53` |
| GetUser | 30 | `map_user()` | `binary_users/mod.rs:49` |
| CreateUser | 31 | `map_user()` | `binary_users/mod.rs:74` |

**패턴**: 같은 데이터 구조를 반환하는 command는 같은 mapper 함수를 사용합니다.
(예: `CreateStream`과 `GetStream` 모두 `StreamDetails`를 반환하므로 `map_stream()` 사용)

#### Lua Dissector 구현 시 고려사항

**좋은 소식**: 순차 처리 덕분에 구현이 매우 단순합니다!

1. **TCP 스트림별로 마지막 요청만 추적**
   - Wireshark의 `pinfo.number` 또는 TCP 스트림 ID 사용
   - 각 TCP 연결마다 "마지막 요청 코드" 하나만 저장하면 됨
   - 큐나 correlation table 불필요 (순차 처리 보장)

2. **방향 구분**
   - 요청: 클라이언트 → 서버 (destination port = 서버 포트)
   - 응답: 서버 → 클라이언트 (source port = 서버 포트)
   - 서버 포트는 설정으로 지정 (기본값: 8090)

3. **요청 파싱 시**
   ```lua
   local code = buffer(4, 4):le_uint()
   -- 단순히 덮어쓰기만 하면 됨 (순차 처리 보장)
   stream_requests[stream_id] = code
   ```

4. **응답 파싱 시**
   ```lua
   local status = buffer(0, 4):le_uint()
   -- 항상 마지막 요청에 대한 응답
   local request_code = stream_requests[stream_id]
   if request_code == 38 then  -- LoginUser
       parse_identity_info(payload)
   elseif request_code == 200 then  -- GetStream
       parse_stream_details(payload)
   end
   ```

5. **주의사항**
   - TCP 재전송 패킷은 Wireshark가 자동으로 표시하므로 별도 처리 불필요
   - 패킷 손실/재조립은 Wireshark의 TCP dissector가 처리
   - 다만, 초기 구현에서는 TCP 세그먼트 재조립 생략 가능 (4.5절 참고)

**참고 파일**: 각 클라이언트 구현 파일에서 요청-mapper 매핑 확인
- `core/binary_protocol/src/client/binary_system/mod.rs`
- `core/binary_protocol/src/client/binary_streams/mod.rs`
- `core/binary_protocol/src/client/binary_users/mod.rs`
- `core/binary_protocol/src/client/binary_messages/mod.rs`

### 3.3 응답 Payload 파싱 ⚠️ 중요!

**응답은 BytesSerializable를 사용하지 않습니다!**

#### 구현 절차
1. **클라이언트 SDK의 mapper 함수 찾기**: `core/binary_protocol/src/utils/mapper.rs`
2. 해당 함수의 바이트 파싱 로직 분석
3. 순차적으로 필드 파싱 (대부분 고정 offset 사용)

#### 서버 vs 클라이언트 mapper

| 역할 | 위치 | 함수 |
|------|------|------|
| 서버 (응답 생성) | `core/server/src/binary/mapper.rs` | `map_stats()`, `map_stream()` 등 |
| 클라이언트 (응답 파싱) | `core/binary_protocol/src/utils/mapper.rs` | `map_stats()`, `map_stream()` 등 |

**Lua 구현 시에는 클라이언트 mapper를 참고해야 합니다!**

#### 예시 1: LoginUser 응답 (Code: 38) - 가장 단순
```rust
// core/binary_protocol/src/utils/mapper.rs:455-465
pub fn map_identity_info(payload: Bytes) -> Result<IdentityInfo, IggyError> {
    let user_id = u32::from_le_bytes(payload[..4].try_into()?);
    Ok(IdentityInfo { user_id, access_token: None })
}
```
- user_id (4 bytes, u32, little-endian)만 파싱

#### 예시 2: GetStream 응답 (Code: 200) - 중간
```rust
// core/binary_protocol/src/utils/mapper.rs:552-573
pub fn map_stream(payload: Bytes) -> Result<StreamDetails, IggyError> {
    let id = u32::from_le_bytes(payload[0..4].try_into()?);
    let created_at = u64::from_le_bytes(payload[4..12].try_into()?).into();
    let topics_count = u32::from_le_bytes(payload[12..16].try_into()?);
    // ... 32 bytes 고정 필드 + name (가변) + topics (반복)
}
```
- 고정 offset에서 순차 파싱
- name: length(1B) + data 패턴
- topics: 반복 구조

#### 예시 3: GetStats 응답 (Code: 10) - 복잡
```rust
// core/binary_protocol/src/utils/mapper.rs:37-350
pub fn map_stats(payload: Bytes) -> Result<Stats, IggyError> {
    // 108 bytes 고정 필드
    let process_id = u32::from_le_bytes(payload[..4].try_into()?);
    let cpu_usage = f32::from_le_bytes(payload[4..8].try_into()?);
    // ...
    let mut current_position = 108;
    // 가변 길이 문자열들 (hostname, os_name, etc)
    let hostname_length = u32::from_le_bytes(...);
    current_position += 4;
    let hostname = String::from_utf8(payload[current_position..].to_vec())?;
    current_position += hostname_length;
    // ... cache_metrics (반복 구조)
}
```
- current_position 추적하며 순차 파싱
- 가변 필드: length(4B) + data
- 반복 필드: count(4B) + entries

### 3.4 공통 데이터 타입

요청/응답 payload에 자주 등장하는 타입들입니다.

#### Identifier
```
+------+--------+-------+
| kind | length | value |
+------+--------+-------+
| 1B   | 1B     | N B   |
```
- kind: 1=Numeric(u32), 2=String(UTF-8)
- **코드**: `core/common/src/types/identifier/mod.rs:216-247`

#### Consumer
```
+------+------------+
| kind | identifier |
+------+------------+
| 1B   | Identifier |
```
- kind: 1=Consumer, 2=ConsumerGroup
- **코드**: `core/common/src/types/consumer/consumer_kind.rs:95-118`

#### PollingStrategy
```
+------+-------+
| kind | value |
+------+-------+
| 1B   | 8B    |
```
- kind: 1=Offset, 2=Timestamp, 3=First, 4=Last, 5=Next
- **코드**: `core/common/src/types/message/polling_strategy.rs`

#### Partitioning
```
+------+--------+-------+
| kind | length | value |
+------+--------+-------+
| 1B   | 1B     | N B   |
```
- kind: 1=Balanced, 2=PartitionId, 3=MessagesKey
- **코드**: `core/common/src/types/message/partitioning.rs:36-149`

---

## 4. 구현 시 주의사항

### 4.1 바이트 순서 (Endianness) ⚠️
- **모든 정수형은 Little-Endian**
- u32, u64, f32 등 모두 `*_le_bytes()` 사용

### 4.2 가변 길이 필드 패턴
| 패턴 | 구조 | 예시 |
|------|------|------|
| 짧은 문자열 | length(1B) + data | Identifier(String), Stream name |
| 긴 문자열 | length(4B) + data | hostname, os_name |
| Optional | length가 0이면 None | LoginUser의 version, context |
| 반복 | count(4B) + entries | topics, cache_metrics |

### 4.3 파싱 순서
1. **고정 크기 필드 먼저**: 정해진 offset에서 직접 읽기
2. **가변 필드는 순차적**: length를 읽고 → data를 읽고 → position 이동
3. **반복 필드**: count를 읽고 → 루프로 각 entry 파싱

### 4.4 에러 처리
- 응답 status가 0이 아니면 에러
- payload가 비어있을 수 있음 (리소스 없음)
- **에러 코드 정의**: `core/common/src/error/iggy_error.rs`

### 4.5 TCP 세그먼트 재조립
- 초기 구현에서는 생략 가능
- 향후 `length` 필드로 메시지 크기 계산 후 `desegment_len` 사용

---

## 5. 구현 워크플로우

### 5.1 새로운 Command 구현하기

#### 1단계: 요청-응답 매핑 확인
```
1. Command 코드 확인 (예: 200 = GET_STREAM)
   → core/common/src/types/command/mod.rs
2. 클라이언트 구현 찾기
   → core/binary_protocol/src/client/binary_streams/mod.rs:32-44
3. 어떤 mapper 함수를 사용하는지 확인
   → get_stream() 메서드에서 mapper::map_stream() 호출
```

#### 2단계: 요청 Payload 파싱
```
1. 요청 struct 구현 찾기
   → core/common/src/commands/streams/get_stream.rs
2. BytesSerializable::to_bytes() 구현 확인
3. Lua로 동일한 순서로 파싱
```

#### 3단계: 응답 Payload 파싱
```
1. 클라이언트 mapper 함수 찾기
   → core/binary_protocol/src/utils/mapper.rs
   → map_stream() 함수
2. 바이트 파싱 로직 분석 (고정 offset, 가변 필드, 반복 구조 등)
3. Lua로 동일한 순서로 파싱
```

### 5.2 디버깅 팁
1. **실제 패킷 캡처**: tshark로 바이너리 확인
2. **테스트 코드 참고**: 각 command의 `#[cfg(test)]` 모듈
   - 예: `core/common/src/commands/system/ping.rs:65-87`
3. **Rust 코드 실행**: 직접 직렬화해보고 hex 덤프 확인

---

## 6. 참고 코드 위치

### 6.1 디렉토리 구조
```
core/
├── common/src/
│   ├── traits/bytes_serializable.rs     # BytesSerializable trait
│   ├── types/
│   │   ├── command/mod.rs               # Command 코드 목록
│   │   ├── identifier/mod.rs            # Identifier
│   │   ├── consumer/consumer_kind.rs    # Consumer
│   │   └── message/
│   │       ├── polling_strategy.rs      # PollingStrategy
│   │       └── partitioning.rs          # Partitioning
│   └── commands/                        # ⭐ 요청 구현 (BytesSerializable)
│       ├── system/ping.rs
│       ├── users/login_user.rs
│       ├── streams/get_stream.rs
│       ├── messages/poll_messages.rs
│       └── ...
├── server/src/
│   ├── binary/
│   │   ├── command.rs                   # ServerCommand enum
│   │   ├── mapper.rs                    # 서버 mapper (응답 생성)
│   │   └── handlers/                    # Command handler
│   └── tcp/sender.rs                    # 응답 전송 로직
└── binary_protocol/src/
    └── utils/mapper.rs                  # ⭐ 클라이언트 mapper (응답 파싱)
```

### 6.2 핵심 파일
| 파일 | 역할 | 용도 |
|------|------|------|
| `core/common/src/commands/**/*.rs` | 요청 직렬화/역직렬화 | 요청 payload 파싱 시 참고 |
| `core/binary_protocol/src/utils/mapper.rs` | 응답 역직렬화 | 응답 payload 파싱 시 참고 ⭐ |
| `core/server/src/binary/mapper.rs` | 응답 직렬화 | 응답 구조 이해용 |
| `core/common/src/types/command/mod.rs` | Command 코드 정의 | 코드↔이름 매핑 |

---

## 7. 구현 우선순위

### 7.1 1단계: 기본 프로토콜
- [x] 요청/응답 헤더 파싱
- [x] Command 코드 식별
- [ ] Status 코드 해석

### 7.2 2단계: 간단한 Command
- [ ] Ping (1) - payload 없음
- [ ] LoginUser (38) - 간단한 문자열
- [ ] GetStream (200) - Identifier 파싱

### 7.3 3단계: 복잡한 Command
- [ ] PollMessages (100) - 여러 공통 타입
- [ ] GetStats (10) - 복잡한 응답
- [ ] SendMessages (101) - 메시지 구조

### 7.4 4단계: 전체 지원
- [ ] 나머지 47개 command
- [ ] TCP 세그먼트 재조립
- [ ] 에러 메시지 상세화

---

## 8. 추가 참고 자료

### 8.1 다른 SDK 구현
- **Python SDK**: (있다면) Python 구현 참고
- **Go SDK**: (있다면) Go 구현 참고

### 8.2 테스트 데이터
- `core/integration/tests/**/*.rs` - 통합 테스트
- 각 command 파일의 `#[cfg(test)]` - 단위 테스트

### 8.3 Wireshark Lua API
- 공식 가이드: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
- 실습 파일: https://gist.github.com/YangSiJun528/df80609ad4b4bcf0375fbe5c92ce5388

---

## 9. 버전 정보

- **작성일**: 2025-11-07
- **기준 코드**: iggy 프로젝트 (commit: f0d3d50e)
- **참고 브랜치**: temp2-feat/custom-wireshark-dissector
- **문서 버전**: 2.0 (Lua Dissector 구현 가이드)
