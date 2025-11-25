# Iggy 파티션-스레드 매핑 분석

## 질문

다이어그램에서는 Partition N → Core #N → Thread #N으로 1:1 매핑처럼 보임
하지만 실제로 파티션 수가 코어 수보다 많으면 어떻게 되는가?
예: 코어 8개인데 파티션이 100개면?

---

## 분석 결과

### 주요 파일 위치

**1. Sharding Configuration:**
- `/core/server/src/configs/sharding.rs`
- `/core/configs/server.toml` (line 543-549)

**2. Core Assignment Logic:**
- `/core/server/src/shard/communication.rs` (lines 193-199)
- `/core/server/src/shard/system/partitions.rs` (lines 103-122)

**3. Main Bootstrap:**
- `/core/server/src/main.rs` (lines 240-420)
- `/core/server/src/bootstrap.rs` (lines 251-374)

**4. Partition Structure:**
- `/core/server/src/streaming/partitions/partition.rs`
- `/core/server/src/shard/namespace.rs`

---

## 파티션-스레드 매핑 메커니즘

### 1. Thread Pool Configuration

**Location:** `/core/server/src/configs/sharding.rs`

시스템은 **"shard-per-core"** 모델을 사용하며, 각 shard는 CPU 코어에 고정된 전용 OS 스레드입니다.

설정 옵션:

```rust
pub enum CpuAllocation {
    All,              // Use all available CPU cores (default)
    Count(usize),     // Use N cores (e.g., 4 = cores 0-3)
    Range(usize, usize), // Use specific range (e.g., 5..8 = cores 5,6,7)
}
```

**설정 파일 (server.toml):**
```toml
[system.sharding]
cpu_allocation = "all"  # Can be "all", a number like 4, or range like "5..8"
```

시스템은 `std::thread::available_parallelism()`를 사용하여 CPU 코어 수를 감지합니다.

### 2. Partition Distribution Algorithm

**Location:** `/core/server/src/shard/communication.rs` (lines 193-199)

```rust
pub fn calculate_shard_assignment(ns: &IggyNamespace, upperbound: u32) -> u16 {
    let mut hasher = Murmur3Hasher::default();
    hasher.write_u64(ns.inner());  // Hash (stream_id, topic_id, partition_id)
    let hash = hasher.finish32();
    // Use middle bits for better distribution
    ((hash >> 16) % upperbound) as u16
}
```

**핵심 포인트:**
- **Murmur3 해시** 사용하여 consistent hashing 구현
- Namespace (stream_id, topic_id, partition_id를 포함한 64비트 값)를 해싱
- 약한 하위 비트를 피하기 위해 중간 비트 사용
- Shard 개수로 modulo 연산하여 할당
- **Round-robin이 아님** - 결정론적 해싱

### 3. Namespace Packing

**Location:** `/core/server/src/shard/namespace.rs`

파티션은 64비트 namespace로 식별됩니다:

```
+----------------+----------------+----------------+----------------+
|   stream_id    |    topic_id    |  partition_id  |     unused     |
|  STREAM_BITS   |   TOPIC_BITS   | PARTITION_BITS |  (64 - total)  |
+----------------+----------------+----------------+----------------+
```

제한사항:
- Max Streams: 4096 (12 bits)
- Max Topics: 4096 (12 bits)
- Max Partitions: 1,000,000 (20 bits)

### 4. 파티션 수 > 코어 수일 때 동작

**Location:** `/core/server/src/shard/system/partitions.rs` (lines 103-122)

파티션 수가 스레드/코어 수를 초과할 때:

1. **여러 파티션이 하나의 shard를 공유** - 해시가 사용 가능한 shard들에 파티션을 분산
2. 각 shard는 consistent hashing을 통해 할당된 **여러 파티션을 처리**
3. Shards 테이블(`DashMap<IggyNamespace, ShardId>`)이 각 파티션을 할당된 shard에 매핑
4. 단일 shard는 할당된 모든 파티션에 대한 작업을 순차적으로 처리

**예시:** 4개 코어에 10개 파티션이 있으면, 코어당 대략 2-3개 파티션 처리

### 5. Shard Execution Model

**Location:** `/core/server/src/main.rs` (lines 358-389)

각 shard는 자체 OS 스레드에서 실행됩니다:

```rust
let handle = std::thread::Builder::new()
    .name(format!("shard-{id}"))
    .spawn(move || {
        let affinity_set = HashSet::from([cpu_id]);
        let rt = create_shard_executor(affinity_set);  // Compio runtime with CPU affinity
        rt.block_on(async move {
            // Shard runs here
        })
    })
```

**주요 특징:**
- Shard당 하나의 **OS 스레드**
- Thread affinity를 사용하여 **특정 CPU 코어에 고정**
  - [what-is-cpu-affinity](https://enterprise-support.nvidia.com/s/article/what-is-cpu-affinity-x)
- **Compio async runtime** 사용 (Linux에서 io_uring, Windows에서 IOCP)
- 각 shard는 자체 async runtime 보유

### 6. Message Routing

**Location:** `/core/server/src/shard/system/messages.rs` (lines 40-144)

메시지가 도착하면:

```rust
// 1. Determine partition based on partitioning strategy
let partition_id = match partitioning.kind {
    PartitioningKind::Balanced => { /* round-robin */ }
    PartitioningKind::PartitionId => { /* explicit */ }
    PartitioningKind::MessagesKey => { /* hash key */ }
};

// 2. Look up which shard owns this partition
let namespace = IggyNamespace::new(stream_id, topic_id, partition_id);
let shard_id = shards_table.get(&namespace);

// 3. Send to that shard (or process locally if current shard)
if shard_id == current_shard {
    // Process directly
} else {
    // Send cross-shard message via channel
}
```

### 7. No Traditional Thread Pool

**중요:** Iggy는 전통적인 work-stealing thread pool을 사용하지 **않습니다**. 대신:

- **Shard-per-core** 아키텍처 사용
- 각 shard는 CPU affinity를 가진 독립적인 worker
- 파티션은 consistent hashing을 통해 shard에 **정적으로 할당**
- Shard 간 work stealing 없음
- 동적 로드 밸런싱 없음

---

## 설정 요약

**기본 동작:**
- 사용 가능한 모든 CPU 코어 사용
- 각 코어는 자체 전용 shard (thread) 보유
- Murmur3 consistent hashing을 통해 파티션 분산

**설정 방법:**
```toml
[system.sharding]
cpu_allocation = "all"     # Use all cores
# cpu_allocation = 4       # Use 4 cores (0-3)
# cpu_allocation = "4..8"  # Use cores 4-7
```

**Bootstrap 위치:** `/core/server/src/bootstrap.rs` (lines 351-374)

시스템은 CPU 할당에 따라 shard를 생성하고, consistent hashing을 통해 파티션을 할당하며, Compio runtime의 thread affinity 지원을 사용하여 각 shard 스레드를 지정된 코어에 고정합니다.

---

## 답변: 파티션 수 > 코어 수일 때 어떻게 동작하는가?

Iggy의 실제 구현을 분석한 결과를 정리하면:

### 핵심 메커니즘

**1. Shard-per-Core 아키텍처**
- 각 CPU 코어당 1개의 Shard(전용 OS 스레드)가 할당됨
- 각 Shard는 특정 코어에 pinning됨 (CPU affinity 사용)
- 기본값: 시스템의 모든 코어 사용

**2. Consistent Hashing으로 파티션 분배**

**코드 위치:** `server/src/shard/communication.rs:193-199`

```rust
pub fn calculate_shard_assignment(ns: &IggyNamespace, upperbound: u32) -> u16 {
    let mut hasher = Murmur3Hasher::default();
    hasher.write_u64(ns.inner());  // (stream_id, topic_id, partition_id) 해싱
    let hash = hasher.finish32();
    ((hash >> 16) % upperbound) as u16  // Shard 수로 modulo 연산
}
```

- **Murmur3 해시** 사용
- Stream ID + Topic ID + Partition ID를 해싱하여 Shard에 할당
- Round-robin이 **아님** - 결정론적 해싱

### 예시: 8개 코어, 100개 파티션

```
Shard 0 (Core 0) → Partitions: 3, 11, 24, 37, 45, 58, 67, 72, 89, 91, 98  (11개)
Shard 1 (Core 1) → Partitions: 1, 15, 22, 33, 44, 51, 60, 78, 85, 92, 99  (11개)
Shard 2 (Core 2) → Partitions: 5, 12, 28, 36, 47, 55, 63, 71, 84, 93      (10개)
...
Shard 7 (Core 7) → Partitions: 8, 19, 26, 39, 48, 56, 68, 77, 88, 96      (10개)
```

- 각 Shard가 **대략 12-13개 파티션**을 처리
- 완벽히 균등하지는 않지만 해시 함수가 고르게 분산시킴

### 동작 방식

**1. 시작 시점 (Bootstrap)**
- 사용 가능한 코어 수만큼 Shard 생성 (예: 8개)
- 각 파티션을 consistent hashing으로 Shard에 할당
- 매핑 테이블(`DashMap<IggyNamespace, ShardId>`) 생성

**2. 메시지 처리**

**코드 위치:** `server/src/shard/system/messages.rs:40-144`

```rust
// 1. 파티션 결정 (partitioning strategy에 따라)
let partition_id = match partitioning.kind {
    PartitioningKind::Balanced => { /* round-robin */ }
    PartitioningKind::MessagesKey => { /* key 기반 해싱 */ }
    PartitioningKind::PartitionId => { /* 명시적 지정 */ }
};

// 2. 해당 파티션이 속한 Shard 찾기
let namespace = IggyNamespace::new(stream_id, topic_id, partition_id);
let shard_id = shards_table.get(&namespace);

// 3. Cross-shard 메시지 전송 또는 직접 처리
if shard_id == current_shard {
    // 현재 Shard에서 직접 처리
} else {
    // 다른 Shard로 메시지 전송 (channel 사용)
}
```

**3. 각 Shard의 처리**
- Shard는 자신에게 할당된 **모든 파티션을 순차 처리**
- 단일 Shard 내에서는 동시성 없음 (shared-nothing)
- 파티션 간 동기화 불필요 → Context switch 최소화

### 설정 방법

**파일:** `configs/server.toml:543-549`

```toml
[system.sharding]
cpu_allocation = "all"     # 모든 코어 사용 (기본값)
# cpu_allocation = 4       # 4개 코어만 사용 (0-3번 코어)
# cpu_allocation = "4..8"  # 4-7번 코어만 사용
```

### 중요한 특징

**1. Work Stealing 없음**
- 전통적인 thread pool과 달리 work stealing 없음
- 파티션은 **고정적으로** 특정 Shard에 할당됨
- 동적 로드 밸런싱 없음

**2. 파티션 제한**
- 최대 파티션 수: **1,000,000개** (20 bits)
- 최대 Stream 수: 4,096개 (12 bits)
- 최대 Topic 수: 4,096개 (12 bits)

**코드 위치:** `server/src/shard/namespace.rs`

**3. io_uring과의 결합**
- 각 Shard는 Compio async runtime 사용
- Linux에서는 io_uring, Windows에서는 IOCP
- 파일 I/O와 네트워크 I/O 모두 비동기 처리

---

## 결론

다이어그램의 `Partition N → Core #N`은 **개념적 설명**이고, 실제로는:

✅ **8개 코어, 100개 파티션인 경우:**
- 8개의 Shard (OS Thread) 생성
- 각 Shard는 대략 12-13개 파티션 담당
- Consistent hashing으로 결정론적 할당
- 각 Shard는 특정 코어에 pinning되어 context switch 최소화

✅ **장점:**
- 파티션 간 lock 불필요
- Cache locality 향상
- Tail latency 예측 가능

✅ **단점:**
- 한 Shard에 핫 파티션이 몰리면 불균형 발생 가능
- 동적 재분배 없음
