# Iggy Binary Protocol Specification

이 문서는 iggy 프로토콜의 바이너리 통신 명세를 정리한 것입니다.
Wireshark Dissector 구현을 위해 작성되었으며, TCP 및 QUIC 통신의 바이너리 포맷을 설명합니다.

## 참고 코드

이 문서는 다음 소스 코드를 분석하여 작성되었습니다:

### 요청(Request) 관련
- **Command 정의**: `core/server/src/binary/command.rs`
  - `define_server_command_enum!` 매크로로 모든 명령어 정의
- **Command 코드 상수**: `core/common/src/types/command/mod.rs`
  - 모든 command code 상수 및 이름 정의
- **BytesSerializable trait**: `core/common/src/traits/bytes_serializable.rs`
  - 직렬화/역직렬화 인터페이스 정의
- **Command 구현 예시**:
  - `core/common/src/commands/system/ping.rs` (간단한 예시)
  - `core/common/src/commands/messages/poll_messages.rs` (복잡한 예시)

### 응답(Response) 관련
- **응답 전송 로직**: `core/server/src/tcp/sender.rs`
  - `send_ok_response()`, `send_error_response()` 함수
  - 응답 바이너리 포맷 구성
- **Sender trait**: `core/server/src/binary/sender.rs`
  - 응답 전송 인터페이스 정의

### 공통 타입
- **Identifier**: `core/common/src/types/identifier/mod.rs`
- **Consumer**: `core/common/src/types/consumer/consumer_kind.rs`
- **기타 BytesSerializable 구현체들**: `core/common/src/types/` 하위 디렉토리

---

## 1. 프로토콜 개요

### 1.1 요청(Request) 포맷

```
+--------+--------+----------+
| length | code   | payload  |
+--------+--------+----------+
| 4B     | 4B     | N bytes  |
| u32    | u32    | variable |
+--------+--------+----------+
```

**필드 설명:**
- `length`: 전체 길이 = code(4 bytes) + payload(N bytes) *(length 자체는 제외)*
- `code`: 요청 코드 (u32, little-endian)
- `payload`: 실제 데이터 (N bytes)

**예시:**
- payload가 100 bytes인 경우
  - `length` = 104 (code 4 + payload 100)
  - 전체 메시지 크기 = 108 bytes (length 4 + code 4 + payload 100)

**코드 출처:**
- `core/server/src/binary/command.rs:151-157`의 `as_bytes()` 함수

### 1.2 응답(Response) 포맷

```
+--------+--------+----------+
| status | length | payload  |
+--------+--------+----------+
| 4B     | 4B     | N bytes  |
| u32    | u32    | variable |
+--------+--------+----------+
```

**필드 설명:**
- `status`: 상태 코드 (u32, little-endian)
  - `0`: 성공 (OK)
  - `0 이외`: 에러 코드 (`IggyError::as_code()`)
- `length`: payload 길이만 (status는 제외, u32, little-endian)
- `payload`: 응답 데이터 (N bytes)
  - status가 에러인 경우: length = 0, payload는 비어있음

**에러 처리:**
- status가 에러 코드인 경우: length = 0, payload 없음
- 존재하지 않는 리소스: status = 0이지만 payload 비어있음

**코드 출처:**
- `core/server/src/tcp/sender.rs:78-98`의 `send_response()` 함수
- `core/server/src/tcp/sender.rs:68-76`의 `send_error_response()` 함수

---

## 2. Command 코드 목록

모든 command 코드는 `core/common/src/types/command/mod.rs`에 정의되어 있습니다.

### 2.1 System Commands (1-19)

| Code | Name | Description |
|------|------|-------------|
| 1 | PING | 서버 상태 확인 |
| 10 | GET_STATS | 서버 통계 조회 |
| 11 | GET_SNAPSHOT_FILE | 스냅샷 파일 조회 |
| 12 | GET_CLUSTER_METADATA | 클러스터 메타데이터 조회 |

### 2.2 User & Client Commands (20-44)

| Code | Name | Description |
|------|------|-------------|
| 20 | GET_ME | 현재 사용자 정보 조회 |
| 21 | GET_CLIENT | 클라이언트 조회 |
| 22 | GET_CLIENTS | 클라이언트 목록 조회 |
| 31 | GET_USER | 사용자 조회 |
| 32 | GET_USERS | 사용자 목록 조회 |
| 33 | CREATE_USER | 사용자 생성 |
| 34 | DELETE_USER | 사용자 삭제 |
| 35 | UPDATE_USER | 사용자 수정 |
| 36 | UPDATE_PERMISSIONS | 권한 수정 |
| 37 | CHANGE_PASSWORD | 비밀번호 변경 |
| 38 | LOGIN_USER | 사용자 로그인 |
| 39 | LOGOUT_USER | 사용자 로그아웃 |
| 41 | GET_PERSONAL_ACCESS_TOKENS | 개인 액세스 토큰 목록 조회 |
| 42 | CREATE_PERSONAL_ACCESS_TOKEN | 개인 액세스 토큰 생성 |
| 43 | DELETE_PERSONAL_ACCESS_TOKEN | 개인 액세스 토큰 삭제 |
| 44 | LOGIN_WITH_PERSONAL_ACCESS_TOKEN | 개인 액세스 토큰으로 로그인 |

### 2.3 Message Commands (100-122)

| Code | Name | Description |
|------|------|-------------|
| 100 | POLL_MESSAGES | 메시지 폴링 |
| 101 | SEND_MESSAGES | 메시지 전송 |
| 102 | FLUSH_UNSAVED_BUFFER | 미저장 버퍼 플러시 |
| 120 | GET_CONSUMER_OFFSET | 컨슈머 오프셋 조회 |
| 121 | STORE_CONSUMER_OFFSET | 컨슈머 오프셋 저장 |
| 122 | DELETE_CONSUMER_OFFSET | 컨슈머 오프셋 삭제 |

### 2.4 Stream Commands (200-205)

| Code | Name | Description |
|------|------|-------------|
| 200 | GET_STREAM | 스트림 조회 |
| 201 | GET_STREAMS | 스트림 목록 조회 |
| 202 | CREATE_STREAM | 스트림 생성 |
| 203 | DELETE_STREAM | 스트림 삭제 |
| 204 | UPDATE_STREAM | 스트림 수정 |
| 205 | PURGE_STREAM | 스트림 퍼지 |

### 2.5 Topic Commands (300-305)

| Code | Name | Description |
|------|------|-------------|
| 300 | GET_TOPIC | 토픽 조회 |
| 301 | GET_TOPICS | 토픽 목록 조회 |
| 302 | CREATE_TOPIC | 토픽 생성 |
| 303 | DELETE_TOPIC | 토픽 삭제 |
| 304 | UPDATE_TOPIC | 토픽 수정 |
| 305 | PURGE_TOPIC | 토픽 퍼지 |

### 2.6 Partition & Segment Commands (402-503)

| Code | Name | Description |
|------|------|-------------|
| 402 | CREATE_PARTITIONS | 파티션 생성 |
| 403 | DELETE_PARTITIONS | 파티션 삭제 |
| 503 | DELETE_SEGMENTS | 세그먼트 삭제 |

### 2.7 Consumer Group Commands (600-605)

| Code | Name | Description |
|------|------|-------------|
| 600 | GET_CONSUMER_GROUP | 컨슈머 그룹 조회 |
| 601 | GET_CONSUMER_GROUPS | 컨슈머 그룹 목록 조회 |
| 602 | CREATE_CONSUMER_GROUP | 컨슈머 그룹 생성 |
| 603 | DELETE_CONSUMER_GROUP | 컨슈머 그룹 삭제 |
| 604 | JOIN_CONSUMER_GROUP | 컨슈머 그룹 가입 |
| 605 | LEAVE_CONSUMER_GROUP | 컨슈머 그룹 탈퇴 |

---

## 3. 공통 데이터 타입

공통 데이터 타입은 `BytesSerializable` trait를 구현하며, 여러 command의 요청/응답 payload에서 재사용됩니다.

### 3.1 Identifier

**구조:**
```
+------+--------+-------+
| kind | length | value |
+------+--------+-------+
| 1B   | 1B     | N B   |
| u8   | u8     | bytes |
+------+--------+-------+
```

**필드:**
- `kind`: Identifier 종류
  - `1`: Numeric (u32, 4 bytes)
  - `2`: String (UTF-8, 1-255 bytes)
- `length`: value 길이 (1-255)
- `value`: 실제 값
  - Numeric인 경우: u32 (little-endian, 4 bytes)
  - String인 경우: UTF-8 바이트 배열 (1-255 bytes)

**사용처:** stream_id, topic_id, user_id 등 거의 모든 리소스 식별

**코드 출처:**
- `core/common/src/types/identifier/mod.rs:216-247`의 `BytesSerializable` 구현

### 3.2 Consumer

**구조:**
```
+------+------------+
| kind | identifier |
+------+------------+
| 1B   | variable   |
| u8   | Identifier |
+------+------------+
```

**필드:**
- `kind`: Consumer 종류
  - `1`: Consumer (일반 컨슈머)
  - `2`: ConsumerGroup (컨슈머 그룹)
- `id`: Identifier (위의 Identifier 구조 참조)

**사용처:** PollMessages, GetConsumerOffset, StoreConsumerOffset 등

**코드 출처:**
- `core/common/src/types/consumer/consumer_kind.rs:95-118`의 `BytesSerializable` 구현

### 3.3 PollingStrategy

**구조:**
```
+------+-------+
| kind | value |
+------+-------+
| 1B   | 8B    |
| u8   | u64   |
+------+-------+
```

**필드:**
- `kind`: Polling 전략 종류
  - `1`: Offset
  - `2`: Timestamp
  - `3`: First
  - `4`: Last
  - `5`: Next
- `value`: 전략에 따른 값 (u64, little-endian)
  - Offset: 시작 오프셋
  - Timestamp: 시작 타임스탬프
  - First/Last/Next: 무시됨 (0)

**사용처:** PollMessages 요청

**코드 출처:**
- `core/common/src/types/message/polling_strategy.rs`

### 3.4 Partitioning

**구조:**
```
+------+--------+-------+
| kind | length | value |
+------+--------+-------+
| 1B   | 1B     | N B   |
| u8   | u8     | bytes |
+------+--------+-------+
```

**필드:**
- `kind`: Partitioning 종류
  - `1`: Balanced (서버에서 round-robin으로 결정)
  - `2`: PartitionId (클라이언트가 파티션 ID 지정)
  - `3`: MessagesKey (메시지 키의 해시로 결정)
- `length`: value 길이 (0-255)
- `value`: 전략에 따른 값
  - Balanced: 비어있음 (length=0)
  - PartitionId: u32 (little-endian, 4 bytes)
  - MessagesKey: 임의의 바이트 배열 (1-255 bytes)

**사용처:** SendMessages 요청

**코드 출처:**
- `core/common/src/types/message/partitioning.rs:36-149`의 `BytesSerializable` 구현

---

## 4. Command Payload 예시

### 4.1 Ping (Code: 1)

**요청 Payload:** 없음 (비어있음)

**응답 Payload:** 없음 (비어있음)

**코드 출처:**
- 요청: `core/common/src/commands/system/ping.rs:44-57`
- 응답: `core/server/src/binary/handlers/system/ping_handler.rs:52`

### 4.2 GetStats (Code: 10)

**요청 Payload:** 없음 (비어있음)

**응답 Payload:** Stats 구조 (고정 크기 + 가변 크기 필드들)

```
+------------+----------+-----------------+-------------+--------------+---------------+
| process_id | cpu_usage| total_cpu_usage | memory_usage| total_memory | available_mem |
+------------+----------+-----------------+-------------+--------------+---------------+
| 4B (u32)   | 4B (f32) | 4B (f32)        | 8B (u64)    | 8B (u64)     | 8B (u64)      |
+------------+----------+-----------------+-------------+--------------+---------------+

+----------+------------+------------+---------------+-------------------+--------------+
| run_time | start_time | read_bytes | written_bytes | messages_size_bytes| streams_count|
+----------+------------+------------+---------------+-------------------+--------------+
| 8B (u64) | 8B (u64)   | 8B (u64)   | 8B (u64)      | 8B (u64)          | 4B (u32)     |
+----------+------------+------------+---------------+-------------------+--------------+

+--------------+-----------------+---------------+------------------+---------------+
| topics_count | partitions_count| segments_count| messages_count   | clients_count |
+--------------+-----------------+---------------+------------------+---------------+
| 4B (u32)     | 4B (u32)        | 4B (u32)      | 8B (u64)         | 4B (u32)      |
+--------------+-----------------+---------------+------------------+---------------+

+------------------------+-----------------+---------+-----------------+---------+
| consumer_groups_count  | hostname_length | hostname| os_name_length  | os_name |
+------------------------+-----------------+---------+-----------------+---------+
| 4B (u32)               | 4B (u32)        | N bytes | 4B (u32)        | N bytes |
+------------------------+-----------------+---------+-----------------+---------+

+------------------+------------+---------------------+--------------------+
| os_version_length| os_version | kernel_version_length| kernel_version   |
+------------------+------------+---------------------+--------------------+
| 4B (u32)         | N bytes    | 4B (u32)            | N bytes           |
+------------------+------------+---------------------+--------------------+

+---------------------------+-------------------------+-------------------+
| iggy_server_version_length| iggy_server_version     | iggy_server_semver|
+---------------------------+-------------------------+-------------------+
| 4B (u32)                  | N bytes                 | 4B (u32), optional|
+---------------------------+-------------------------+-------------------+

+--------------------+------------------+
| cache_metrics_count| cache_metrics... |
+--------------------+------------------+
| 4B (u32)           | N entries        |
+--------------------+------------------+
```

**Cache Metrics 엔트리 구조 (반복):**
```
+-----------+----------+--------------+------+--------+-----------+
| stream_id | topic_id | partition_id | hits | misses | hit_ratio |
+-----------+----------+--------------+------+--------+-----------+
| 4B (u32)  | 4B (u32) | 4B (u32)     | 8B   | 8B     | 4B (f32)  |
+-----------+----------+--------------+------+--------+-----------+
```

**코드 출처:**
- 응답: `core/server/src/binary/mapper.rs:33-79`

### 4.3 GetStream (Code: 200)

**요청 Payload:**
```
+-----------+
| stream_id |
+-----------+
| Identifier|
+-----------+
```

**응답 Payload:** Stream 구조

```
+-----------+------------+--------------+------+----------------+
| stream_id | created_at | topics_count | size | messages_count |
+-----------+------------+--------------+------+----------------+
| 4B (u32)  | 8B (u64)   | 4B (u32)     | 8B   | 8B (u64)       |
+-----------+------------+--------------+------+----------------+

+-------------+------+
| name_length | name |
+-------------+------+
| 1B (u8)     | N B  |
+-------------+------+

+--------------------+
| topics (repeated)  |
+--------------------+
| topics_count 만큼   |
+--------------------+
```

**Topic 구조 (Stream 응답에 포함, 반복):**
```
+----------+------------+------------------+----------------+
| topic_id | created_at | partitions_count | message_expiry |
+----------+------------+------------------+----------------+
| 4B (u32) | 8B (u64)   | 4B (u32)         | 8B (u64)       |
+----------+------------+------------------+----------------+

+-----------------------+----------------+--------------------+
| compression_algorithm | max_topic_size | replication_factor |
+-----------------------+----------------+--------------------+
| 1B (u8)               | 8B (u64)       | 1B (u8)            |
+-----------------------+----------------+--------------------+

+-----------+----------------+-------------+------+
| size      | messages_count | name_length | name |
+-----------+----------------+-------------+------+
| 8B (u64)  | 8B (u64)       | 1B (u8)     | N B  |
+-----------+----------------+-------------+------+
```

**코드 출처:**
- 요청: `core/common/src/commands/streams/get_stream.rs:50-63`
- 응답: `core/server/src/binary/mapper.rs:153-160, 213-235`

### 4.4 LoginUser (Code: 38)

**요청 Payload:**
```
+-----------------+----------+-----------------+----------+
| username_length | username | password_length | password |
+-----------------+----------+-----------------+----------+
| 1B (u8)         | N bytes  | 1B (u8)         | N bytes  |
+-----------------+----------+-----------------+----------+

+----------------+---------+----------------+---------+
| version_length | version | context_length | context |
+----------------+---------+----------------+---------+
| 4B (u32)       | N bytes | 4B (u32)       | N bytes |
+----------------+---------+----------------+---------+
```

**필드:**
- `username_length`: 사용자명 길이 (u8)
- `username`: 사용자명 (UTF-8, 3-50 bytes)
- `password_length`: 비밀번호 길이 (u8)
- `password`: 비밀번호 (UTF-8, 3-100 bytes)
- `version_length`: 버전 문자열 길이 (u32, 0이면 None)
- `version`: SDK 버전 (UTF-8, optional)
- `context_length`: 컨텍스트 문자열 길이 (u32, 0이면 None)
- `context`: 컨텍스트 메타데이터 (UTF-8, optional)

**응답 Payload:** UserId (4 bytes)
```
+---------+
| user_id |
+---------+
| 4B (u32)|
+---------+
```

**코드 출처:**
- 요청: `core/common/src/commands/users/login_user.rs:82-110`
- 응답: `core/server/src/binary/mapper.rs:132-136`

### 4.5 PollMessages (Code: 100)

**요청 Payload 구조:**
```
+----------+-----------+----------+--------------+----------+-------+-------------+
| consumer | stream_id | topic_id | partition_id | strategy | count | auto_commit |
+----------+-----------+----------+--------------+----------+-------+-------------+
| Consumer | Identifier| Identifier| 4B (u32)    | Strategy | 4B    | 1B          |
+----------+-----------+----------+--------------+----------+-------+-------------+
```

**필드:**
- `consumer`: Consumer 타입 (위의 Consumer 구조 참조)
- `stream_id`: Stream Identifier
- `topic_id`: Topic Identifier
- `partition_id`: 파티션 ID (u32, little-endian)
  - `0`: None (컨슈머 그룹용)
  - `1~`: 파티션 ID
- `strategy`: PollingStrategy (위의 PollingStrategy 구조 참조)
- `count`: 폴링할 메시지 수 (u32, little-endian)
- `auto_commit`: 자동 커밋 여부 (u8)
  - `0`: false
  - `1`: true

**응답 Payload 구조:**
```
+--------------+----------------+----------------+-----------+
| partition_id | current_offset | messages_count | messages  |
+--------------+----------------+----------------+-----------+
| 4B (u32)     | 8B (u64)       | 4B (u32)       | variable  |
+--------------+----------------+----------------+-----------+
```

**코드 출처:**
- 요청: `core/common/src/commands/messages/poll_messages.rs:138-206`
- 응답: `core/server/src/binary/handlers/messages/poll_messages_handler.rs:78-96`

### 4.6 SendMessages (Code: 101)

**요청 Payload 구조:**
```
+-----------------+-----------+----------+--------------+----------------+
| metadata_length | stream_id | topic_id | partitioning | messages_count |
+-----------------+-----------+----------+--------------+----------------+
| 4B (u32)        | Identifier| Identifier| Partitioning| 4B (u32)       |
+-----------------+-----------+----------+--------------+----------------+

+---------+-----------+
| indexes | messages  |
+---------+-----------+
| N * 16B | variable  |
+---------+-----------+
```

**필드:**
- `metadata_length`: stream_id + topic_id + partitioning + messages_count 길이의 합
- `stream_id`: Stream Identifier
- `topic_id`: Topic Identifier
- `partitioning`: Partitioning (위의 Partitioning 구조 참조)
- `messages_count`: 메시지 개수 (u32)
- `indexes`: 각 메시지의 인덱스 정보 (16 bytes * messages_count)
  - 각 인덱스: offset(8B) + length(4B) + timestamp(4B)
- `messages`: 실제 메시지 데이터들

**응답 Payload:** 없음 (빈 OK 응답)

**코드 출처:**
- 요청: `core/common/src/commands/messages/send_messages.rs:58-119`
- 응답: Handler에서 `send_empty_ok_response()` 호출

---

## 5. 구현 시 주의사항

### 5.1 바이트 순서 (Endianness)

- 모든 정수형은 **Little-Endian** 형식을 사용합니다.
- `u32`, `u64` 등 숫자는 `to_le_bytes()` / `from_le_bytes()`로 처리됩니다.

### 5.2 가변 길이 타입

- `Identifier`, `Consumer` 등은 가변 길이 타입입니다.
- 파싱 시 `length` 필드를 먼저 읽고, 해당 길이만큼 `value`를 읽어야 합니다.

### 5.3 TCP 세그먼트 재조립

- 현재 이 명세는 TCP 세그먼트 재조립을 고려하지 않습니다.
- 향후 구현 시 `length` 필드를 기반으로 전체 메시지 크기를 계산하고,
  Wireshark의 `desegment_len`을 사용하여 구현할 수 있습니다.

### 5.4 에러 코드

- 에러 코드 정의는 `core/common/src/error/iggy_error.rs`에 있습니다.
- HTTP 변환 코드는 `core/server/src/http/error.rs`에 있습니다.
  (Dissector에는 직접 필요 없지만 참고용)

---

## 6. 응답 포맷의 특징 (매우 중요!)

### 6.1 응답은 순수 바이너리 포맷 (JSON 아님)

iggy 프로토콜의 응답은 **JSON이 아닌 순수 바이너리 포맷**입니다.

### 6.2 응답은 BytesSerializable를 사용하지 않음

대부분의 응답 payload는 `BytesSerializable` trait를 사용하지 않고, **서버와 클라이언트에 각각 수동으로 구현된 직렬화/역직렬화 로직**이 있습니다.

#### 서버 측 (응답 직렬화)
`core/server/src/binary/mapper.rs`의 mapper 함수들이 직접 바이트로 구성:

- `map_stats()` - GetStats 응답
- `map_stream()` - GetStream 응답
- `map_streams()` - GetStreams 응답
- `map_topic()` - GetTopic 응답
- `map_topics()` - GetTopics 응답
- `map_user()` - GetUser 응답
- `map_users()` - GetUsers 응답
- `map_client()` - GetClient 응답
- `map_clients()` - GetClients 응답
- `map_consumer_group()` - GetConsumerGroup 응답
- `map_consumer_groups()` - GetConsumerGroups 응답
- `map_consumer_offset()` - GetConsumerOffset 응답
- `map_identity_info()` - LoginUser 응답
- `map_raw_pat()` - CreatePersonalAccessToken 응답
- `map_personal_access_tokens()` - GetPersonalAccessTokens 응답

#### 클라이언트 SDK (응답 역직렬화)
`core/binary_protocol/src/utils/mapper.rs`의 mapper 함수들이 바이트를 파싱:

**예시 1: `map_identity_info()` (LoginUser 응답 역직렬화)**
```rust
pub fn map_identity_info(payload: Bytes) -> Result<IdentityInfo, IggyError> {
    let user_id = u32::from_le_bytes(payload[..4].try_into()?);
    Ok(IdentityInfo { user_id, access_token: None })
}
```
- payload의 처음 4 bytes를 u32로 파싱하여 user_id 추출

**예시 2: `map_stream()` (GetStream 응답 역직렬화)**
```rust
pub fn map_stream(payload: Bytes) -> Result<StreamDetails, IggyError> {
    let id = u32::from_le_bytes(payload[0..4].try_into()?);
    let created_at = u64::from_le_bytes(payload[4..12].try_into()?).into();
    let topics_count = u32::from_le_bytes(payload[12..16].try_into()?);
    let size_bytes = u64::from_le_bytes(payload[16..24].try_into()?).into();
    let messages_count = u64::from_le_bytes(payload[24..32].try_into()?);
    let name_length = payload[32] as usize;
    let name = String::from_utf8(payload[33..33 + name_length].to_vec())?;
    // ... topics 파싱 ...
}
```
- 고정된 바이트 위치에서 각 필드를 순차적으로 파싱

**예시 3: `map_stats()` (GetStats 응답 역직렬화)**
- 108 bytes의 고정 크기 필드들 + 가변 길이 문자열들 + 캐시 메트릭스
- `current_position` 변수로 파싱 위치를 추적하며 순차 파싱
- 가변 길이 필드는 "length + data" 패턴 사용

### 6.3 요청과 응답의 비대칭성

| | 요청 (Request) | 응답 (Response) |
|---|---|---|
| 직렬화 방식 | `BytesSerializable` trait | 수동 mapper 함수 |
| 역직렬화 방식 | `BytesSerializable` trait | 수동 mapper 함수 |
| 구현 위치 | `core/common/src/commands/**/*.rs` | 서버: `core/server/src/binary/mapper.rs`클라이언트: `core/binary_protocol/src/utils/mapper.rs` |
| 구조 | 구조화된 타입 | 최적화된 바이너리 포맷 |

**설계 이유:**
- 응답 직렬화 성능 최적화
- 서버에서 불필요한 trait 구현 제거
- 더 유연한 바이너리 포맷 제어

### 6.4 Wireshark Dissector 구현 시 주의사항

응답 payload를 파싱할 때는:
1. **클라이언트 SDK의 mapper 함수를 참고**해야 함 (`core/binary_protocol/src/utils/mapper.rs`)
2. BytesSerializable 구현체를 찾아도 응답 파싱에는 사용할 수 없음
3. 각 command마다 서버 mapper와 클라이언트 mapper를 **쌍으로** 분석해야 정확한 포맷을 알 수 있음

**바이트 파싱 패턴:**
- 고정 크기 필드: 정해진 offset에서 직접 읽기
- 가변 길이 필드: `length (u32 또는 u8) + data` 패턴
- 반복 필드: `count (u32) + entries` 패턴
- 중첩 구조: 순차적으로 파싱하며 position 추적

---

## 7. 향후 작업

### 7.1 전체 Command Payload 명세

- 현재 문서는 6개 command만 상세히 다룹니다 (Ping, GetStats, GetStream, LoginUser, PollMessages, SendMessages)
- 나머지 44개 command의 payload 구조를 문서화해야 합니다
- 우선순위: 자주 사용되는 command부터 (CreateStream, CreateTopic, GetConsumerOffset 등)

### 7.2 Message 타입 명세

- PollMessages 응답과 SendMessages 요청에 포함되는 실제 메시지 데이터 구조
- IggyMessage, IggyMessagesBatch 등의 바이너리 포맷
- Message Header 구조

### 7.3 추가 공통 타입

다음 타입들은 BytesSerializable를 구현하지만 아직 문서화되지 않음:
- ConsumerOffsetInfo - GetConsumerOffset 응답에 사용
- 기타 필요시 추가

---

## 8. 참고 자료

### 8.1 주요 소스 파일 위치

```
core/
├── common/src/
│   ├── traits/bytes_serializable.rs     # BytesSerializable trait 정의
│   ├── types/
│   │   ├── command/mod.rs               # Command 코드 상수 정의
│   │   ├── identifier/mod.rs            # Identifier 구현
│   │   ├── consumer/consumer_kind.rs    # Consumer 구현
│   │   └── ...
│   └── commands/                        # Command 구현체들
│       ├── system/ping.rs
│       ├── messages/poll_messages.rs
│       └── ...
└── server/src/
    ├── binary/
    │   ├── command.rs                   # ServerCommand enum 정의
    │   ├── sender.rs                    # Sender trait 정의
    │   └── handlers/                    # Command handler 구현
    └── tcp/
        └── sender.rs                    # 응답 전송 로직

```

### 8.2 테스트 코드

- 각 command 구현 파일의 `#[cfg(test)]` 모듈에 직렬화/역직렬화 테스트가 있습니다.
- 예: `core/common/src/commands/system/ping.rs:65-87`
- 예: `core/common/src/commands/messages/poll_messages.rs:228-321`

---

## 9. 버전 정보

- **작성일**: 2025-11-07
- **기준 코드**: iggy 프로젝트 최신 버전 (commit: f0d3d50e)
- **참고 브랜치**: temp2-feat/custom-wireshark-dissector
