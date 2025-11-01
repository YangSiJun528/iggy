# IGGY Protocol Specification

## 목차
1. [프로토콜 개요](#프로토콜-개요)
2. [메시지 프레임 구조](#메시지-프레임-구조)
3. [커맨드 코드](#커맨드-코드)
4. [공통 데이터 타입](#공통-데이터-타입)
5. [커맨드별 페이로드 구조](#커맨드별-페이로드-구조)

---

## 프로토콜 개요

### 기본 특성
- **전송 계층**: TCP (기본 포트: 8090), QUIC 지원
- **바이트 순서**: Little Endian
- **통신 패턴**: Request-Response
- **상태**: Stateful (로그인 필요)
- **TLS**: 지원 (선택적)

### 소스 참조
- TCP Client: `core/sdk/src/tcp/tcp_client.rs`
- Command Definitions: `core/common/src/types/command/mod.rs`
- Binary Server: `core/server/src/binary/command.rs`

---

## 메시지 프레임 구조

### Request 프레임

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Length (u32 LE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Command (u32 LE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Payload (Variable)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**필드 설명:**
- **Length** (4 bytes): 전체 메시지 길이 (Command 4바이트 포함)
- **Command** (4 bytes): 커맨드 코드 (1-605)
- **Payload** (Variable): 커맨드별 페이로드 (길이 = Length - 4)

**소스**: `core/sdk/src/tcp/tcp_client.rs:497-501`

### Response 프레임

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Status (u32 LE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Length (u32 LE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Payload (Variable)                       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**필드 설명:**
- **Status** (4 bytes): 응답 상태 (0 = 성공, 0 이외 = 에러 코드)
- **Length** (4 bytes): 페이로드 길이 (0 또는 1 = 빈 응답)
- **Payload** (Variable): 응답 데이터

**소스**: `core/sdk/src/tcp/tcp_client.rs:204-245`

---

## 커맨드 코드

**소스**: `core/common/src/types/command/mod.rs`

### System Commands (1-22)

| Code | Name | Description |
|------|------|-------------|
| 1 | PING | 서버 연결 확인 |
| 10 | GET_STATS | 서버 통계 조회 |
| 11 | GET_SNAPSHOT_FILE | 스냅샷 파일 조회 |
| 12 | GET_CLUSTER_METADATA | 클러스터 메타데이터 조회 |
| 20 | GET_ME | 현재 클라이언트 정보 조회 |
| 21 | GET_CLIENT | 특정 클라이언트 정보 조회 |
| 22 | GET_CLIENTS | 모든 클라이언트 목록 조회 |

### User Management (31-44)

| Code | Name | Description |
|------|------|-------------|
| 31 | GET_USER | 사용자 정보 조회 |
| 32 | GET_USERS | 모든 사용자 목록 조회 |
| 33 | CREATE_USER | 새 사용자 생성 |
| 34 | DELETE_USER | 사용자 삭제 |
| 35 | UPDATE_USER | 사용자 정보 수정 |
| 36 | UPDATE_PERMISSIONS | 권한 수정 |
| 37 | CHANGE_PASSWORD | 비밀번호 변경 |
| 38 | LOGIN_USER | 사용자 로그인 |
| 39 | LOGOUT_USER | 사용자 로그아웃 |
| 41 | GET_PERSONAL_ACCESS_TOKENS | PAT 목록 조회 |
| 42 | CREATE_PERSONAL_ACCESS_TOKEN | PAT 생성 |
| 43 | DELETE_PERSONAL_ACCESS_TOKEN | PAT 삭제 |
| 44 | LOGIN_WITH_PERSONAL_ACCESS_TOKEN | PAT로 로그인 |

### Message Operations (100-122)

| Code | Name | Description |
|------|------|-------------|
| 100 | POLL_MESSAGES | 메시지 조회 (풀링) |
| 101 | SEND_MESSAGES | 메시지 전송 |
| 102 | FLUSH_UNSAVED_BUFFER | 저장되지 않은 버퍼 플러시 |
| 120 | GET_CONSUMER_OFFSET | Consumer 오프셋 조회 |
| 121 | STORE_CONSUMER_OFFSET | Consumer 오프셋 저장 |
| 122 | DELETE_CONSUMER_OFFSET | Consumer 오프셋 삭제 |

### Stream Management (200-205)

| Code | Name | Description |
|------|------|-------------|
| 200 | GET_STREAM | 스트림 정보 조회 |
| 201 | GET_STREAMS | 모든 스트림 목록 조회 |
| 202 | CREATE_STREAM | 새 스트림 생성 |
| 203 | DELETE_STREAM | 스트림 삭제 |
| 204 | UPDATE_STREAM | 스트림 수정 |
| 205 | PURGE_STREAM | 스트림 데이터 삭제 |

### Topic Management (300-305)

| Code | Name | Description |
|------|------|-------------|
| 300 | GET_TOPIC | 토픽 정보 조회 |
| 301 | GET_TOPICS | 토픽 목록 조회 |
| 302 | CREATE_TOPIC | 새 토픽 생성 |
| 303 | DELETE_TOPIC | 토픽 삭제 |
| 304 | UPDATE_TOPIC | 토픽 수정 |
| 305 | PURGE_TOPIC | 토픽 데이터 삭제 |

### Partition Management (402-403)

| Code | Name | Description |
|------|------|-------------|
| 402 | CREATE_PARTITIONS | 파티션 생성 |
| 403 | DELETE_PARTITIONS | 파티션 삭제 |

### Segment Management (503)

| Code | Name | Description |
|------|------|-------------|
| 503 | DELETE_SEGMENTS | 세그먼트 삭제 |

### Consumer Group Management (600-605)

| Code | Name | Description |
|------|------|-------------|
| 600 | GET_CONSUMER_GROUP | Consumer Group 정보 조회 |
| 601 | GET_CONSUMER_GROUPS | Consumer Group 목록 조회 |
| 602 | CREATE_CONSUMER_GROUP | Consumer Group 생성 |
| 603 | DELETE_CONSUMER_GROUP | Consumer Group 삭제 |
| 604 | JOIN_CONSUMER_GROUP | Consumer Group 참여 |
| 605 | LEAVE_CONSUMER_GROUP | Consumer Group 탈퇴 |

---

## 공통 데이터 타입

### Identifier

**소스**: `core/common/src/types/identifier/mod.rs`

Stream ID, Topic ID, User ID 등에 사용되는 식별자 구조

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Kind (u8)    |  Length (u8)  |     Value (max 255 bytes)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Kind 값:**
- `1` = Numeric: Value는 u32 (4 bytes, LE)
- `2` = String: Value는 UTF-8 문자열 (Length 바이트)

**예시:**
```
Numeric ID (123):
  01 04 7B 00 00 00

String ID ("stream1"):
  02 07 73 74 72 65 61 6D 31
```

### Partitioning

**소스**: `core/common/src/types/message/partitioning.rs`

메시지를 어느 파티션으로 보낼지 지정

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Kind (u8)    |  Length (u8)  |     Value (max 255 bytes)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Kind 값:**
- `1` = Balanced: 라운드 로빈 (Length = 0, Value 없음)
- `2` = PartitionId: 특정 파티션 (Value = u32 파티션 ID)
- `3` = MessagesKey: 해시 키 (Value = 키 바이트)

### Consumer

Consumer 종류 지정 (poll_messages에서 사용)

```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Kind (u8)    |  Consumer ID  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Kind 값:**
- `1` = Consumer: 개별 Consumer (Identifier 포함)
- `2` = ConsumerGroup: Consumer Group (Identifier 포함)

### Polling Strategy

메시지 조회 시작 위치 지정

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Kind (u8)    |               Value (u64 LE)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         (continued)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Kind 값:**
- `1` = Offset: 특정 오프셋부터 (Value = offset)
- `2` = Timestamp: 특정 시간 이후 (Value = timestamp)
- `3` = First: 처음부터 (Value = 0)
- `4` = Last: 마지막부터 (Value = 0)
- `5` = Next: 다음 메시지부터 (Value = 0)

### String Types

**1바이트 길이 (u8):**
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Length (u8)  |           UTF-8 String (max 255)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**4바이트 길이 (u32):**
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Length (u32 LE)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     UTF-8 String (Variable)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 커맨드별 페이로드 구조

### PING (1)

**소스**: `core/common/src/commands/system/ping.rs`

**Request Payload:**
```
(Empty - 0 bytes)
```

**Response Payload:**
```
(Empty - Status 0, Length 0)
```

### LOGIN_USER (38)

**소스**: `core/common/src/commands/users/login_user.rs`

**Request Payload:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Username Len  |        Username (UTF-8, 3-50 chars)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Password Len  |        Password (UTF-8, 3-100 chars)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Version Length (u32 LE)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Version String (Optional)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Context Length (u32 LE)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Context String (Optional)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**필드:**
- Username: 1바이트 길이 + UTF-8 문자열
- Password: 1바이트 길이 + UTF-8 문자열
- Version: 4바이트 길이 + UTF-8 문자열 (선택적, Length=0이면 없음)
- Context: 4바이트 길이 + UTF-8 문자열 (선택적, Length=0이면 없음)

**Response Payload:**
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          User ID                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Access Token (Variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### CREATE_STREAM (202)

**소스**: `core/common/src/commands/streams/create_stream.rs`

**Request Payload:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Stream ID (u32 LE)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Name Length  |          Name (UTF-8, 1-255 chars)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**필드:**
- Stream ID: u32 (0 = 자동 할당)
- Name: 1바이트 길이 + UTF-8 문자열

### POLL_MESSAGES (100)

**소스**: `core/common/src/commands/messages/poll_messages.rs`

**Request Payload:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Consumer Kind  |            Consumer (Identifier)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream (Identifier)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Topic (Identifier)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Partition ID (u32 LE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Strategy Kind  |         Strategy Value (u64 LE)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         (continued)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Count (u32 LE)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Auto Commit   |
+-+-+-+-+-+-+-+-+
```

**필드:**
- Consumer Kind: 1=Consumer, 2=ConsumerGroup
- Consumer: Identifier
- Stream: Identifier
- Topic: Identifier
- Partition ID: u32 (0 = N/A for consumer groups)
- Strategy Kind: 1=Offset, 2=Timestamp, 3=First, 4=Last, 5=Next
- Strategy Value: u64
- Count: 조회할 메시지 수
- Auto Commit: 1=true, 0=false

### SEND_MESSAGES (101)

**소스**: `core/common/src/commands/messages/send_messages.rs`

**Request Payload:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Metadata Length (u32 LE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream (Identifier)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Topic (Identifier)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Partitioning (Variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Messages Count (u32 LE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Index Table (16 bytes * N)                  |
|              (8B reserved + 4B size + 4B reserved)            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Messages Data (Variable)                   |
|                   (serialized message batch)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**필드:**
- Metadata Length: stream_id + topic_id + partitioning + messages_count 크기
- Stream: Identifier
- Topic: Identifier
- Partitioning: Partitioning 구조
- Messages Count: 메시지 개수
- Index Table: 각 메시지당 16바이트
  - 8 bytes: Reserved
  - 4 bytes: Cumulative size (누적 크기)
  - 4 bytes: Reserved
- Messages Data: 실제 메시지 데이터

### GET_STREAM (200)

**Request Payload:**
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream (Identifier)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### CREATE_TOPIC (302)

**Request Payload:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream (Identifier)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Topic ID (u32 LE)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Partitions Count (u32 LE)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Name Length  |          Name (UTF-8, 1-255 chars)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Message Expiry (u32 LE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                Max Topic Size (u64 LE, Optional)              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Replication   |
+-+-+-+-+-+-+-+-+
```

### STORE_CONSUMER_OFFSET (121)

**Request Payload:**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Consumer Kind  |            Consumer (Identifier)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Stream (Identifier)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Topic (Identifier)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Partition ID (u32 LE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Offset (u64 LE)                        |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 에러 코드

Response Status != 0일 때 에러 발생

**주요 에러:**
- Authentication errors (Unauthenticated, StaleClient)
- Resource conflicts (TopicAlreadyExists, StreamAlreadyExists)
- Protocol errors (InvalidCommand, InvalidNumberEncoding)
- Not found errors (TopicNotFound, StreamNotFound)

**소스**: `core/sdk/src/tcp/tcp_client.rs:209-234`

---

## TCP 재조립 고려사항

- 큰 메시지는 여러 TCP 세그먼트로 분할될 수 있음
- Length 필드를 읽어 전체 메시지 크기 파악
- 불완전한 메시지는 다음 세그먼트를 대기해야 함
- Wireshark의 `desegment_len` 사용

---

## 참고 문서

- IGGY Repository: https://github.com/iggy-rs/iggy
- Command Definitions: `core/common/src/types/command/mod.rs`
- TCP Implementation: `core/sdk/src/tcp/tcp_client.rs`
- Binary Serialization: `core/common/src/traits/bytes_serializable.rs`

---

*Last Updated: 2025-11-02*
