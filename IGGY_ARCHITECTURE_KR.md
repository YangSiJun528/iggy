# Apache Iggy 아키텍처 가이드 (한국어)

## 목차
1. [Iggy란 무엇인가?](#1-iggy란-무엇인가)
2. [메시징 시스템 기초 개념](#2-메시징-시스템-기초-개념)
3. [핵심 아키텍처](#3-핵심-아키텍처)
4. [데이터 모델과 계층 구조](#4-데이터-모델과-계층-구조)
5. [메시지 저장 메커니즘](#5-메시지-저장-메커니즘)
6. [코드 구조 분석](#6-코드-구조-분석)
7. [성능 최적화 기법](#7-성능-최적화-기법)
8. [실전 예제](#8-실전-예제)

---

## 1. Iggy란 무엇인가?

### 1.1 개요
**Apache Iggy**는 Rust로 작성된 **지속성 메시지 스트리밍 플랫폼**입니다. Kafka나 RabbitMQ와 같은 메시징 시스템과 유사하지만, 다음과 같은 차별점이 있습니다:

- **처음부터 새로 작성**: Kafka 위에 구축된 확장이 아님
- **초저지연**: 마이크로초 단위의 tail latency (p99+)
- **초고성능**: 초당 수백만 메시지 처리 가능 (5M+ msg/sec)
- **최소 리소스**: Rust의 제로코스트 추상화와 GC 없는 메모리 관리
- **다중 프로토콜**: QUIC, TCP, HTTP 지원

### 1.2 왜 만들어졌는가?
전통적인 메시징 시스템들의 한계:
- **Kafka**: JVM 기반으로 GC 오버헤드, 높은 메모리 사용량
- **RabbitMQ**: 낮은 처리량, 복잡한 클러스터링
- **Redis Streams**: 제한적인 지속성, 메모리 기반

Iggy는 이러한 한계를 극복하기 위해 **로우레벨 I/O 최적화**와 **Rust의 성능**을 활용합니다.

---

## 2. 메시징 시스템 기초 개념

메시징 시스템에 익숙하지 않다면, 먼저 기본 개념을 이해해야 합니다.

### 2.1 메시징 시스템이란?

**메시징 시스템**은 애플리케이션 간 비동기 통신을 가능하게 하는 미들웨어입니다.

```
[Producer] --메시지--> [메시징 시스템] --메시지--> [Consumer]
```

**왜 필요한가?**
- **디커플링**: Producer와 Consumer가 서로를 알 필요 없음
- **확장성**: Consumer를 독립적으로 스케일 가능
- **신뢰성**: 메시지가 손실되지 않고 저장됨
- **비동기 처리**: Producer는 응답을 기다리지 않음

### 2.2 핵심 용어

#### 메시지 (Message)
- 전송하려는 데이터의 단위
- 예: JSON 객체, 바이너리 데이터, 이벤트

#### Producer (생산자)
- 메시지를 **보내는** 애플리케이션
- 예: 주문 시스템이 "주문 생성됨" 이벤트를 발행

#### Consumer (소비자)
- 메시지를 **읽는** 애플리케이션
- 예: 재고 시스템이 주문 이벤트를 구독하여 재고 감소

#### Topic (토픽)
- 메시지를 **분류하는 카테고리**
- 예: `orders`, `payments`, `user-events`

#### Offset (오프셋)
- 메시지의 **순차적 위치**
- 각 메시지는 0부터 시작하는 고유 번호를 가짐
- Consumer는 offset을 추적하여 어디까지 읽었는지 기억

### 2.3 Kafka와 비교

Kafka를 알고 있다면, Iggy를 더 쉽게 이해할 수 있습니다:

| 개념 | Kafka | Iggy |
|------|-------|------|
| 최상위 그룹 | Cluster | System |
| 네임스페이스 | (없음) | **Stream** |
| 메시지 카테고리 | Topic | Topic |
| 병렬 처리 단위 | Partition | Partition |
| 파일 단위 | Segment | Segment |
| 소비자 그룹 | Consumer Group | Consumer Group |

**주요 차이점:**
- **Iggy는 Stream 개념 추가**: 멀티테넌시를 위한 추가 계층
- **바이너리 데이터 직접 처리**: 스키마 강제 없음
- **Zero-copy serialization**: 메모리 복사 최소화

---

## 3. 핵심 아키텍처

### 3.1 High-Level 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                     Iggy Server                          │
├─────────────────────────────────────────────────────────┤
│  Transport Layer (QUIC / TCP / HTTP)                     │
├─────────────────────────────────────────────────────────┤
│  Authentication & Authorization                          │
├─────────────────────────────────────────────────────────┤
│  System (전체 서버 상태)                                  │
│  ├── Streams (멀티테넌트 네임스페이스)                     │
│  │   ├── Topics (메시지 카테고리)                         │
│  │   │   ├── Partitions (병렬 처리 단위)                  │
│  │   │   │   ├── Segments (파일 저장 단위)                │
│  ├── Users & Permissions                                 │
│  ├── Consumer Groups                                     │
│  └── Metrics & Diagnostics                               │
└─────────────────────────────────────────────────────────┘
```

### 3.2 시스템 구조 (코드 기반)

`core/server/src/streaming/systems/system.rs:78` 참조:

```rust
pub struct System {
    pub permissioner: Permissioner,           // 권한 관리
    pub(crate) storage: Arc<SystemStorage>,   // 스토리지 추상화
    pub(crate) streams: AHashMap<u32, Stream>,     // Stream ID -> Stream
    pub(crate) streams_ids: AHashMap<String, u32>, // Stream Name -> ID
    pub(crate) users: AHashMap<UserId, User>,      // 사용자 관리
    pub(crate) config: Arc<SystemConfig>,          // 설정
    pub(crate) client_manager: IggySharedMut<ClientManager>, // 클라이언트 연결
    pub(crate) encryptor: Option<Arc<EncryptorKind>>,        // 암호화
    pub(crate) metrics: Metrics,                             // 메트릭
    pub(crate) state: Arc<StateKind>,                        // 영속 상태
    pub(crate) archiver: Option<Arc<ArchiverKind>>,         // 백업/아카이브
}
```

**핵심 포인트:**
- `System`은 **전체 서버의 최상위 객체**
- 모든 `Stream`을 소유하고 관리
- **Shared-nothing 아키텍처**를 향해 개선 중 (io_uring 지원 예정)

---

## 4. 데이터 모델과 계층 구조

### 4.1 계층 구조 상세

```
System
  └── Stream (예: "production", "analytics")
       └── Topic (예: "orders", "events")
            └── Partition (예: 1, 2, 3)
                 └── Segment (예: 0.log, 1000.log)
                      └── Messages (실제 데이터)
```

### 4.2 Stream (스트림)

`core/server/src/streaming/streams/stream.rs:30` 참조:

```rust
pub struct Stream {
    pub stream_id: u32,                      // 고유 ID
    pub name: String,                        // 이름 (예: "dev", "prod")
    pub path: String,                        // 파일시스템 경로
    pub topics_path: String,                 // Topics 디렉토리
    pub created_at: IggyTimestamp,           // 생성 시간
    pub current_topic_id: AtomicU32,         // 다음 Topic ID
    pub size_bytes: Arc<AtomicU64>,          // 총 크기 (바이트)
    pub messages_count: Arc<AtomicU64>,      // 총 메시지 수
    pub segments_count: Arc<AtomicU32>,      // 총 세그먼트 수
    pub(crate) topics: AHashMap<u32, Topic>, // Topic ID -> Topic
    pub(crate) topics_ids: AHashMap<String, u32>, // Topic Name -> ID
}
```

**Stream의 역할:**
- **멀티테넌시**: 서로 다른 애플리케이션/팀을 격리
- **네임스페이스**: Topic 이름 충돌 방지
- **리소스 격리**: 각 Stream은 독립적인 디렉토리

**실제 파일 구조 예시:**
```
local_data/
  └── streams/
       ├── 1/  (stream ID)
       │   ├── stream.info
       │   └── topics/
       │        ├── 1/  (topic ID)
       │        └── 2/
       └── 2/
```

### 4.3 Topic (토픽)

`core/server/src/streaming/topics/topic.rs:40` 참조:

```rust
pub struct Topic {
    pub stream_id: u32,                      // 부모 Stream ID
    pub topic_id: u32,                       // 고유 ID
    pub name: String,                        // 이름 (예: "orders")
    pub path: String,                        // 파일시스템 경로
    pub partitions_path: String,             // Partitions 디렉토리
    pub(crate) size_bytes: Arc<AtomicU64>,   // Topic 크기
    pub(crate) messages_count: Arc<AtomicU64>, // 메시지 수
    pub(crate) partitions: AHashMap<u32, IggySharedMut<Partition>>,
    pub(crate) consumer_groups: AHashMap<u32, RwLock<ConsumerGroup>>,
    pub message_expiry: IggyExpiry,          // 메시지 만료 정책
    pub compression_algorithm: CompressionAlgorithm, // 압축
    pub max_topic_size: MaxTopicSize,        // 최대 크기 제한
}
```

**Topic의 역할:**
- **메시지 분류**: 관련된 메시지들을 그룹화
- **Consumer Group 관리**: 여러 Consumer의 협력 처리
- **메시지 만료**: 오래된 데이터 자동 삭제
- **압축**: 저장 공간 절약 (none, gzip, zstd 등)

### 4.4 Partition (파티션)

`core/server/src/streaming/partitions/partition.rs:35` 참조:

```rust
pub struct Partition {
    pub stream_id: u32,
    pub topic_id: u32,
    pub partition_id: u32,                   // Partition 번호
    pub partition_path: String,              // 파일 경로
    pub current_offset: u64,                 // 현재 offset
    pub message_deduplicator: Option<MessageDeduplicator>, // 중복 제거
    pub unsaved_messages_count: u32,         // 아직 디스크에 안 쓴 메시지
    pub unsaved_messages_size: IggyByteSize,
    pub avg_timestamp_delta: IggyDuration,   // 평균 시간 간격
    pub(crate) consumer_offsets: DashMap<u32, ConsumerOffset>,       // Consumer별 offset
    pub(crate) consumer_group_offsets: DashMap<u32, ConsumerOffset>, // Group별 offset
    pub(crate) segments: Vec<Segment>,       // Segment 목록
    pub message_expiry: IggyExpiry,
}
```

**Partition의 역할:**
- **병렬 처리**: 여러 Consumer가 동시에 다른 Partition을 읽음
- **순서 보장**: **같은 Partition 내에서만** 메시지 순서 보장
- **Offset 추적**: Consumer가 어디까지 읽었는지 기록
- **중복 제거**: 동일 메시지의 중복 저장 방지

**Partition 선택 방법:**
```rust
// Producer가 메시지를 보낼 때 Partition 결정
pub enum Partitioning {
    Balanced,              // 라운드로빈으로 분산
    PartitionId(u32),      // 특정 Partition 지정
    MessageKey,            // 메시지 키의 해시값으로 결정
}
```

**예시:**
- 사용자 ID를 키로 사용하면, 같은 사용자의 메시지는 항상 같은 Partition으로
- 이를 통해 **특정 사용자의 이벤트 순서 보장**

### 4.5 Segment (세그먼트)

`core/server/src/streaming/segments/segment.rs:38` 참조:

```rust
pub struct Segment {
    pub(super) stream_id: u32,
    pub(super) topic_id: u32,
    pub(super) partition_id: u32,
    pub(super) start_offset: u64,           // 시작 offset
    pub(super) end_offset: u64,             // 끝 offset
    pub(super) start_timestamp: u64,        // 첫 메시지 시각
    pub(super) end_timestamp: u64,          // 마지막 메시지 시각
    pub(super) index_path: String,          // 인덱스 파일 (.index)
    pub(super) messages_path: String,       // 메시지 파일 (.log)
    pub(super) max_size_bytes: IggyByteSize, // 최대 크기 (예: 1GB)
    pub(super) is_closed: bool,             // 닫힘 여부
    pub(super) messages_writer: Option<MessagesWriter>,
    pub(super) messages_reader: Option<MessagesReader>,
    pub(super) index_writer: Option<IndexWriter>,
    pub(super) index_reader: Option<IndexReader>,
    pub(super) indexes: IggyIndexesMut,     // 메모리 인덱스
    pub(super) accumulator: MessagesAccumulator, // 배치 버퍼
}
```

**Segment의 역할:**
- **파일 단위 저장**: 무한정 커지는 파일 방지
- **효율적인 삭제**: 오래된 Segment 통째로 삭제
- **인덱스 관리**: 빠른 offset 검색을 위한 인덱스

**파일 구조 예시:**
```
partition_1/
  ├── 0.log         (offset 0~999 메시지)
  ├── 0.index       (offset -> file position 매핑)
  ├── 1000.log      (offset 1000~1999 메시지)
  ├── 1000.index
  ├── 2000.log
  └── 2000.index
```

**Segment 생성 조건:**
- 현재 Segment가 최대 크기에 도달 (예: 1GB)
- 또는 시간 기반 정책 (예: 24시간마다)

---

## 5. 메시지 저장 메커니즘

### 5.1 메시지 쓰기 플로우

```
1. Producer → IggyServer
   ↓
2. Partition 선택 (Partitioning 전략)
   ↓
3. Active Segment 확인
   ↓
4. MessagesAccumulator에 배치 (batch)
   ↓
5. Flush 조건 충족 시 디스크에 쓰기
   ↓
6. Index 업데이트 (offset → file position)
   ↓
7. Consumer offset 알림
```

### 5.2 Append-Only Log 구조

Iggy는 **Append-Only Log**를 사용합니다:

```
[Header][Payload][Header][Payload][Header][Payload] ...
```

**메시지 포맷:**
```rust
// 각 메시지는 다음 구조로 저장
struct StoredMessage {
    offset: u64,           // 8 bytes
    timestamp: u64,        // 8 bytes (microseconds)
    id: u128,              // 16 bytes (UUID)
    checksum: u32,         // 4 bytes (CRC32)
    headers_len: u32,      // 4 bytes
    headers: Vec<Header>,  // 가변 길이
    payload_len: u32,      // 4 bytes
    payload: Vec<u8>,      // 가변 길이 (실제 메시지)
}
```

**왜 Append-Only인가?**
- **순차 쓰기**: 디스크의 가장 빠른 I/O 패턴
- **불변성**: 메시지는 절대 수정되지 않음 (이벤트 소싱 철학)
- **간단한 복구**: 파일 끝에서 다시 시작

### 5.3 인덱스 시스템

**문제:**
"offset 123456에 있는 메시지를 읽고 싶은데, 파일에서 어디부터 읽어야 하나?"

**해결:** 인덱스 파일 (`.index`)

```rust
// 인덱스 엔트리
struct IndexEntry {
    relative_offset: u32,  // Segment 내 상대 offset
    position: u32,         // 파일 내 바이트 위치
}
```

**예시:**
```
0.log (1GB, offset 0 ~ 999999)
0.index:
  offset 0     → position 0
  offset 1000  → position 4096
  offset 2000  → position 8192
  ...
```

**인덱스 검색 알고리즘:**
1. Binary search로 offset에 가까운 인덱스 찾기
2. 해당 position으로 seek
3. 선형 스캔으로 정확한 offset 찾기

**시간 인덱스:**
- offset 외에도 **timestamp로 메시지 검색** 가능
- 예: "2025년 10월 31일 10:00 이후 메시지"
- 별도의 `.timeindex` 파일

### 5.4 배치 쓰기 (Batching)

성능을 위해 **배치 단위로 디스크에 쓰기**:

```rust
pub struct MessagesAccumulator {
    messages: Vec<Message>,
    total_size: usize,
    batch_size: usize,        // 예: 1000개
    max_wait_time: Duration,  // 예: 10ms
}
```

**Flush 조건:**
- 배치 크기 도달 (예: 1000개 메시지)
- OR 타임아웃 (예: 10ms 경과)
- OR Producer가 명시적으로 flush 요청

**trade-off:**
- 배치 크기 ↑ → 처리량 ↑, 지연시간 ↑
- 배치 크기 ↓ → 처리량 ↓, 지연시간 ↓

### 5.5 Zero-Copy 최적화

Iggy는 **메모리 복사를 최소화**합니다:

```rust
// 전통적인 방식 (여러 번 복사)
TCP → Kernel Buffer → User Buffer → Serialization Buffer → Disk Buffer → Disk

// Zero-Copy 방식
TCP → Kernel Buffer → (mmap) → Direct I/O → Disk
```

**기술:**
- `mmap`: 파일을 메모리에 직접 매핑
- `sendfile`: 커널 공간에서 직접 네트워크 → 파일
- Custom binary protocol: protobuf/JSON 오버헤드 없음

---

## 6. 코드 구조 분석

### 6.1 프로젝트 구조

```
iggy/
├── core/
│   ├── server/           # 서버 메인 로직
│   │   └── src/
│   │       ├── archiver/         # S3 백업
│   │       ├── binary/           # TCP 프로토콜 핸들러
│   │       ├── http/             # HTTP API
│   │       ├── quic/             # QUIC 프로토콜
│   │       ├── streaming/        # 핵심 스트리밍 로직
│   │       │   ├── systems/      # System 관리
│   │       │   ├── streams/      # Stream 관리
│   │       │   ├── topics/       # Topic 관리
│   │       │   ├── partitions/   # Partition 관리
│   │       │   ├── segments/     # Segment 관리
│   │       │   ├── storage/      # 스토리지 추상화
│   │       │   ├── clients/      # 클라이언트 세션
│   │       │   └── users/        # 인증/권한
│   │       └── state/            # 서버 상태 영속화
│   │
│   ├── sdk/              # Rust 클라이언트 SDK
│   │   └── src/
│   │       ├── clients/          # 프로토콜별 클라이언트
│   │       ├── consumer_ext/     # High-level Consumer API
│   │       └── stream_builder/   # Fluent API
│   │
│   ├── binary_protocol/  # 커스텀 바이너리 프로토콜
│   ├── common/           # 공통 타입 및 유틸
│   ├── cli/              # CLI 도구
│   ├── bench/            # 벤치마크 도구
│   │   ├── runner/       # 벤치마크 실행기
│   │   ├── dashboard/    # 벤치마크 시각화
│   │   └── report/       # 결과 분석
│   │
│   └── connectors/       # 외부 시스템 연동
│       ├── sdk/          # Connector 개발 SDK
│       ├── runtime/      # 동적 플러그인 로더
│       ├── sinks/        # 데이터 내보내기
│       │   ├── postgres_sink/
│       │   ├── quickwit_sink/
│       │   └── stdout_sink/
│       └── sources/      # 데이터 가져오기
│           ├── postgres_source/
│           └── random_source/
│
├── foreign/              # 다른 언어 SDK
│   ├── go/
│   ├── python/
│   ├── node/
│   └── java/
│
└── examples/             # 예제 코드
    └── rust/
```

### 6.2 핵심 모듈 분석

#### 6.2.1 System 모듈

**파일:** `core/server/src/streaming/systems/system.rs`

**책임:**
- 전체 서버 상태 관리
- Stream, User, Client 관리
- 권한 검사 (Permissioner)
- 메트릭 수집

**주요 메서드:**
```rust
impl System {
    // Stream 생성
    pub async fn create_stream(&mut self, name: &str) -> Result<Stream, IggyError>

    // Stream 조회
    pub fn get_stream(&self, id: &Identifier) -> Result<&Stream, IggyError>

    // 메시지 append
    pub async fn append_messages(
        &mut self,
        stream_id: &Identifier,
        topic_id: &Identifier,
        partition_id: &Identifier,
        messages: Vec<Message>,
    ) -> Result<(), IggyError>

    // 메시지 poll
    pub async fn poll_messages(
        &self,
        consumer: &Consumer,
        stream_id: &Identifier,
        topic_id: &Identifier,
        partition_id: &Identifier,
        strategy: &PollingStrategy,
        count: u32,
    ) -> Result<PolledMessages, IggyError>
}
```

#### 6.2.2 Segment 모듈

**파일:** `core/server/src/streaming/segments/segment.rs`

**책임:**
- 파일 읽기/쓰기
- 인덱스 관리
- 메시지 배치 처리

**핵심 구현:**
```rust
impl Segment {
    // 메시지 append (배치)
    pub async fn append_batch(&mut self, messages: &[Arc<RetainedMessage>])
        -> Result<(), IggyError> {
        // 1. Accumulator에 추가
        self.accumulator.add_messages(messages);

        // 2. Flush 조건 확인
        if self.accumulator.should_flush() {
            self.flush_messages().await?;
        }
        Ok(())
    }

    // 디스크에 실제 쓰기
    async fn flush_messages(&mut self) -> Result<(), IggyError> {
        let messages = self.accumulator.drain();

        // 메시지 파일에 쓰기
        self.messages_writer.write(messages).await?;

        // 인덱스 업데이트
        self.update_indexes().await?;

        // fsync (설정에 따라)
        if self.config.partition.enforce_fsync {
            self.messages_writer.sync().await?;
        }
        Ok(())
    }

    // Offset으로 메시지 읽기
    pub async fn read_messages(
        &self,
        start_offset: u64,
        count: u32,
    ) -> Result<Vec<Message>, IggyError> {
        // 1. 인덱스에서 파일 위치 찾기
        let position = self.indexes.get_position(start_offset)?;

        // 2. 파일에서 읽기
        let mut reader = self.messages_reader.as_ref().unwrap();
        reader.seek(position).await?;

        let mut messages = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let message = reader.read_message().await?;
            messages.push(message);
        }

        Ok(messages)
    }
}
```

#### 6.2.3 Partition 모듈

**파일:** `core/server/src/streaming/partitions/partition.rs`

**책임:**
- Segment 관리 (생성, 닫기, 삭제)
- Consumer offset 추적
- 메시지 중복 제거

**Segment 롤링:**
```rust
impl Partition {
    async fn maybe_roll_segment(&mut self) -> Result<(), IggyError> {
        let current_segment = self.segments.last_mut().unwrap();

        // Segment 크기가 최대치에 도달했는지 확인
        if current_segment.size() >= current_segment.max_size_bytes {
            // 현재 Segment 닫기
            current_segment.close().await?;

            // 새 Segment 생성
            let next_offset = current_segment.end_offset + 1;
            let new_segment = Segment::create(
                self.stream_id,
                self.topic_id,
                self.partition_id,
                next_offset,
                self.config.clone(),
                // ...
            );

            self.segments.push(new_segment);
            info!("Created new segment at offset {}", next_offset);
        }

        Ok(())
    }
}
```

### 6.3 Connectors 시스템

Iggy의 **Connectors**는 외부 시스템과 데이터를 주고받는 플러그인 시스템입니다.

**아키텍처:**
```
┌──────────────┐      ┌───────────────────┐      ┌──────────────┐
│   Source     │ ───> │  Iggy Connector   │ ───> │     Sink     │
│ (Postgres)   │      │     Runtime       │      │ (Quickwit)   │
└──────────────┘      └───────────────────┘      └──────────────┘
                              │
                              ├─ Transforms (데이터 변환)
                              │   ├─ add_fields
                              │   ├─ delete_fields
                              │   ├─ filter_fields
                              │   └─ proto_convert
                              │
                              └─ 동적 플러그인 로딩
```

**Source Connector 예시** (`core/connectors/sources/random_source/`):
```rust
use iggy_connector_sdk::{Source, SourceConfig, DecodedMessage};

pub struct RandomSource {
    config: RandomSourceConfig,
    message_count: u64,
}

#[async_trait]
impl Source for RandomSource {
    async fn read(&mut self) -> Result<Vec<DecodedMessage>, Error> {
        // 랜덤 데이터 생성
        let messages = (0..self.config.batch_size)
            .map(|_| self.generate_random_message())
            .collect();

        Ok(messages)
    }

    fn source_type(&self) -> SourceType {
        SourceType::Random
    }
}
```

**Sink Connector 예시** (`core/connectors/sinks/postgres_sink/`):
```rust
use iggy_connector_sdk::{Sink, SinkConfig, DecodedMessage};

pub struct PostgresSink {
    pool: PgPool,
    config: PostgresSinkConfig,
}

#[async_trait]
impl Sink for PostgresSink {
    async fn write(&mut self, messages: Vec<DecodedMessage>) -> Result<(), Error> {
        // Batch insert into PostgreSQL
        let mut tx = self.pool.begin().await?;

        for msg in messages {
            sqlx::query("INSERT INTO events (data, timestamp) VALUES ($1, $2)")
                .bind(&msg.payload)
                .bind(msg.timestamp)
                .execute(&mut tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }
}
```

**Transform 예시** (`core/connectors/sdk/src/transforms/add_fields.rs`):
```rust
pub struct AddFields {
    fields: Vec<AddField>,
}

impl Transform for AddFields {
    fn transform(
        &self,
        metadata: &TopicMetadata,
        mut message: DecodedMessage,
    ) -> Result<Option<DecodedMessage>, Error> {
        // JSON 파싱
        let mut json: serde_json::Value =
            serde_json::from_slice(&message.payload)?;

        // 필드 추가
        for field in &self.fields {
            match &field.value {
                FieldValue::Static(v) => {
                    json[&field.key] = v.clone();
                },
                FieldValue::Computed(ComputedValue::UuidV7) => {
                    json[&field.key] = uuid::Uuid::now_v7().to_string().into();
                },
                FieldValue::Computed(ComputedValue::TimestampMillis) => {
                    json[&field.key] = chrono::Utc::now().timestamp_millis().into();
                },
                // ...
            }
        }

        message.payload = serde_json::to_vec(&json)?;
        Ok(Some(message))
    }
}
```

**동적 플러그인 로딩** (`core/connectors/runtime/`):
```rust
// Rust 컴파일된 .so/.dylib/.dll 동적 로드
use dlopen2::wrapper::{Container, WrapperApi};

#[derive(WrapperApi)]
struct SinkApi {
    create_sink: fn(config: &str) -> Box<dyn Sink>,
}

// Runtime에서 플러그인 로드
let container: Container<SinkApi> =
    unsafe { Container::load("libiggy_connector_postgres_sink.so")? };

let sink = container.create_sink(&config_json);
```

---

## 7. 성능 최적화 기법

### 7.1 Rust의 Zero-Cost Abstraction

Iggy는 Rust의 장점을 최대한 활용합니다:

```rust
// 1. Arena 할당 (메모리 fragmentation 방지)
use bumpalo::Bump;
let arena = Bump::new();
let messages = arena.alloc_slice_fill_with(1000, |_| Message::new());

// 2. Stack 할당 최대화
#[inline(always)]
fn parse_message(bytes: &[u8]) -> Result<Message, Error> {
    // Heap 할당 없이 파싱
}

// 3. SIMD 연산 (simd-json)
use simd_json::to_owned_value;
let json: OwnedValue = to_owned_value(bytes)?;
```

### 7.2 Lock-Free 자료구조

**DashMap** (concurrent HashMap):
```rust
// 전통적인 RwLock<HashMap> 대신
pub(crate) consumer_offsets: DashMap<u32, ConsumerOffset>

// 여러 스레드에서 동시에 접근 가능, lock contention 없음
offsets.insert(consumer_id, offset);
```

**Atomic 연산:**
```rust
pub size_bytes: Arc<AtomicU64>

// Lock 없이 counter 증가
self.size_bytes.fetch_add(message_size, Ordering::Relaxed);
```

### 7.3 배치 처리

**메시지 배치 쓰기:**
```rust
// 나쁜 예: 메시지마다 syscall
for msg in messages {
    file.write(msg).await?;  // 1000번의 write syscall
}

// 좋은 예: 배치로 한 번에
let batch = messages.iter().flat_map(|m| m.to_bytes()).collect();
file.write_all(&batch).await?;  // 1번의 write syscall
```

### 7.4 메모리 풀링

**BytesMut 재사용:**
```rust
pub struct MessagesAccumulator {
    buffer: BytesMut,  // 메시지 직렬화 버퍼
}

impl MessagesAccumulator {
    pub fn drain(&mut self) -> BytesMut {
        // 버퍼 내용을 빼내되, capacity는 유지
        self.buffer.split()  // Zero-copy
    }
}
```

### 7.5 I/O 최적화

**Direct I/O (계획 중):**
```rust
// 커널 페이지 캐시 우회, 직접 디스크 접근
use nix::fcntl::{OFlag, O_DIRECT};
let fd = open(path, O_DIRECT | O_WRONLY)?;
```

**io_uring (계획 중):**
```rust
// Linux 비동기 I/O, 시스템콜 오버헤드 최소화
use io_uring::{IoUring, opcode};
let ring = IoUring::new(256)?;
ring.submission().push(opcode::Write::new(fd, buffer));
ring.submit_and_wait(1)?;
```

### 7.6 벤치마크 결과

공식 벤치마크 플랫폼: https://benchmarks.iggy.apache.org

**전형적인 성능 (AMD Ryzen 9, NVMe SSD):**
- **쓰기 처리량**: 5M+ messages/sec (~5GB/sec)
- **읽기 처리량**: 10M+ messages/sec (~10GB/sec)
- **Tail latency (p99)**: < 1ms
- **Tail latency (p99.9)**: < 5ms

**Kafka와 비교:**
- **3-5배 높은 처리량**
- **10배 낮은 latency**
- **50% 적은 메모리 사용**

---

## 8. 실전 예제

### 8.1 기본 Producer/Consumer

```rust
use iggy::client::IggyClient;
use iggy::messages::send_messages::{Message, Partitioning};
use iggy::consumer::Consumer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 클라이언트 생성 (TCP 연결)
    let client = IggyClient::from_connection_string(
        "iggy://iggy:iggy@localhost:8090"
    )?;

    // Stream과 Topic 생성
    client.create_stream("orders", None).await?;
    client.create_topic("orders", "new-orders", 3, /* 3 partitions */
        None, None, None, None).await?;

    // ===== Producer =====
    let messages = vec![
        Message::new(None, b"Order #1".to_vec(), None),
        Message::new(None, b"Order #2".to_vec(), None),
        Message::new(None, b"Order #3".to_vec(), None),
    ];

    client.send_messages(
        "orders",
        "new-orders",
        &Partitioning::balanced(),  // 라운드로빈
        &mut messages.into_iter().map(|m| m.into()).collect(),
    ).await?;

    println!("✅ Sent 3 messages");

    // ===== Consumer =====
    let consumer = Consumer::new(1); // Consumer ID = 1

    let polled = client.poll_messages(
        "orders",
        "new-orders",
        Some(0),  // Partition 0
        &consumer,
        &PollingStrategy::offset(0),  // Offset 0부터
        10,  // 최대 10개
        false,  // auto-commit 안 함
    ).await?;

    for msg in polled.messages {
        println!("📨 Received: {}", String::from_utf8_lossy(&msg.payload));
    }

    Ok(())
}
```

### 8.2 High-Level API (Producer/Consumer Builder)

```rust
use iggy::client::IggyClient;
use iggy::IggyDuration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = IggyClient::from_connection_string("iggy://iggy:iggy@localhost:8090")?;

    // ===== Producer (배치 설정) =====
    let mut producer = client
        .producer("orders", "new-orders")?
        .direct(
            DirectConfig::builder()
                .batch_length(1000)  // 1000개씩 배치
                .linger_time(IggyDuration::from_str("10ms")?)  // 또는 10ms 대기
                .build()
        )
        .partitioning(Partitioning::balanced())
        .build();

    producer.init().await?;

    // 메시지 전송 (자동으로 배치 처리됨)
    for i in 0..10000 {
        let msg = IggyMessage::from_str(&format!("Order #{}", i))?;
        producer.send(vec![msg]).await?;
    }

    producer.flush().await?;  // 남은 메시지 강제 flush

    // ===== Consumer Group =====
    let mut consumer = client
        .consumer_group("order-processor", "orders", "new-orders")?
        .auto_commit(AutoCommit::IntervalOrWhen(
            IggyDuration::from_str("5s")?,  // 5초마다 자동 커밋
            AutoCommitWhen::ConsumingAllMessages,
        ))
        .create_consumer_group_if_not_exists()  // Group 없으면 생성
        .auto_join_consumer_group()  // 자동 조인
        .polling_strategy(PollingStrategy::next())  // 다음 메시지부터
        .poll_interval(IggyDuration::from_str("100ms")?)
        .batch_length(100)  // 100개씩 poll
        .build();

    consumer.init().await?;

    // 메시지 소비 (무한 루프)
    while let Some(message) = consumer.next().await {
        let payload = String::from_utf8_lossy(&message.payload);
        println!("Processing: {}", payload);

        // 비즈니스 로직 처리
        process_order(&payload).await?;
    }

    Ok(())
}

async fn process_order(order: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 주문 처리 로직
    Ok(())
}
```

### 8.3 Consumer Group (수평 확장)

**Consumer Group**은 여러 Consumer가 협력하여 메시지를 처리하는 방식입니다.

```rust
// Consumer 1 (프로세스 1)
let mut consumer1 = client
    .consumer_group("payment-service", "orders", "new-orders")?
    .consumer_id(1)
    .build();

consumer1.init().await?;

while let Some(msg) = consumer1.next().await {
    // Partition 0, 3, 6, 9... 처리
}

// Consumer 2 (프로세스 2)
let mut consumer2 = client
    .consumer_group("payment-service", "orders", "new-orders")?
    .consumer_id(2)
    .build();

consumer2.init().await?;

while let Some(msg) = consumer2.next().await {
    // Partition 1, 4, 7, 10... 처리
}

// Consumer 3 (프로세스 3)
let mut consumer3 = client
    .consumer_group("payment-service", "orders", "new-orders")?
    .consumer_id(3)
    .build();

consumer3.init().await?;

while let Some(msg) = consumer3.next().await {
    // Partition 2, 5, 8, 11... 처리
}
```

**작동 방식:**
- Partition이 Consumer에게 자동으로 분배됨
- Consumer가 추가되면 rebalancing 발생
- 하나의 Partition은 한 Consumer만 읽음 (순서 보장)

### 8.4 메시지 키를 이용한 순서 보장

```rust
// 같은 사용자의 이벤트는 항상 같은 Partition으로
let user_id = "user_123";
let message = Message::new(
    None,
    serde_json::to_vec(&Order {
        user_id: user_id.to_string(),
        amount: 100.0,
    })?,
    Some(user_id.as_bytes().to_vec()),  // 메시지 키
);

client.send_messages(
    "orders",
    "new-orders",
    &Partitioning::message_key(),  // 키의 해시값으로 Partition 결정
    &mut vec![message.into()],
).await?;
```

**결과:**
- `user_123`의 모든 주문은 항상 같은 Partition에 저장
- 따라서 해당 Partition을 읽는 Consumer는 순서를 보장받음

### 8.5 Connector 설정 예시

**config.toml:**
```toml
# PostgreSQL에서 읽어서 Iggy로 전송
[sources.postgres]
enabled = true
name = "User events from PostgreSQL"
path = "target/release/libiggy_connector_postgres_source.dylib"
config_format = "yaml"

[[sources.postgres.streams]]
stream = "analytics"
topic = "user-events"
connection_string = "postgresql://user:pass@localhost/mydb"
table = "user_events"
poll_interval = "1s"

# Iggy에서 읽어서 Quickwit(검색엔진)로 전송
[sinks.quickwit]
enabled = true
name = "Quickwit sink for logs"
path = "target/release/libiggy_connector_quickwit_sink.dylib"
config_format = "yaml"

[[sinks.quickwit.streams]]
stream = "logs"
topics = ["application", "nginx"]
schema = "json"
batch_length = 1000
poll_interval = "5ms"
consumer_group = "quickwit_indexer"

# Transform: 필드 추가
[[sinks.quickwit.transforms.add_fields.fields]]
key = "ingested_at"
value.computed = "timestamp_millis"

[[sinks.quickwit.transforms.add_fields.fields]]
key = "trace_id"
value.computed = "uuid_v7"

# Transform: 민감한 필드 삭제
[sinks.quickwit.transforms.delete_fields]
enabled = true
fields = ["password", "credit_card", "ssn"]
```

---

## 9. 고급 주제

### 9.1 메시지 만료 (Message Expiry)

```rust
use iggy::IggyExpiry;

// Topic 생성 시 만료 정책 설정
client.create_topic(
    "orders",
    "old-orders",
    3,
    None,
    Some(IggyExpiry::ExpireDuration(IggyDuration::from_str("7d")?)),  // 7일 후 삭제
    None,
    None,
).await?;
```

**만료 메커니즘:**
- 백그라운드 스레드가 주기적으로 Segment 스캔
- `end_timestamp`가 현재 시간 - expiry보다 오래되면 Segment 삭제
- 개별 메시지가 아닌 **Segment 단위로 삭제** (효율성)

### 9.2 데이터 암호화

**서버 사이드 암호화:**
```toml
# server.toml
[encryption]
enabled = true
key = "base64-encoded-aes-256-key"  # 32 bytes
```

**클라이언트 사이드 암호화:**
```rust
use iggy::messages::send_messages::Message;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

let cipher = Aes256Gcm::new(key.into());
let nonce = Nonce::from_slice(b"unique nonce");

let plaintext = b"sensitive data";
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;

let message = Message::new(None, ciphertext, None);
client.send_messages(...).await?;
```

### 9.3 백업 및 아카이빙

**S3 자동 백업:**
```toml
# server.toml
[archiver]
enabled = true
kind = "s3"
interval = "1h"  # 1시간마다

[archiver.s3]
bucket = "iggy-backups"
region = "us-east-1"
access_key_id = "YOUR_ACCESS_KEY"
secret_access_key = "YOUR_SECRET"
```

**수동 백업:**
```bash
# 전체 데이터 디렉토리 압축
tar -czf iggy-backup-$(date +%Y%m%d).tar.gz local_data/
```

### 9.4 메트릭 및 모니터링

**Prometheus 메트릭:**
```toml
[metrics]
enabled = true
endpoint = "0.0.0.0:9090"
```

**주요 메트릭:**
- `iggy_messages_sent_total`: 전송된 메시지 수
- `iggy_messages_received_total`: 수신된 메시지 수
- `iggy_bytes_sent_total`: 전송된 바이트 수
- `iggy_segments_count`: 현재 Segment 수
- `iggy_disk_usage_bytes`: 디스크 사용량

**OpenTelemetry 추적:**
```toml
[tracing]
enabled = true
endpoint = "http://localhost:4317"
```

---

## 10. 결론

### 10.1 Iggy의 장점 요약

1. **성능**: Rust의 zero-cost abstraction + 저수준 I/O 최적화
2. **단순성**: 단일 바이너리 배포, 외부 의존성 없음
3. **유연성**: QUIC/TCP/HTTP, 멀티 언어 SDK
4. **확장성**: Consumer Group, 수평 확장
5. **신뢰성**: Append-only log, fsync 옵션, 데이터 암호화

### 10.2 언제 사용해야 하는가?

**Iggy가 적합한 경우:**
- 초저지연이 중요한 실시간 시스템
- 높은 처리량이 필요한 이벤트 스트리밍
- 리소스 제약이 있는 환경 (IoT, 엣지)
- 간단한 배포와 운영이 필요한 경우

**Kafka가 더 나은 경우:**
- 성숙한 생태계가 필요 (Kafka Streams, Connect)
- 다중 데이터센터 복제
- 대규모 클러스터 운영 경험이 있는 팀

### 10.3 로드맵

- **Clustering**: Viewstamped Replication (VSR) 기반
- **io_uring**: Linux 비동기 I/O 지원
- **Shared-nothing 아키텍처**: CPU 코어당 독립적인 스레드
- **Tiered Storage**: Hot/Cold 데이터 분리 (S3 통합)

### 10.4 참고 자료

- **공식 문서**: https://iggy.apache.org/docs/
- **GitHub**: https://github.com/apache/iggy
- **Discord**: https://discord.gg/C5Sux5NcRa
- **벤치마크**: https://benchmarks.iggy.apache.org

---

**작성 일자**: 2025-10-31
**버전**: Iggy 0.7.0 기준
