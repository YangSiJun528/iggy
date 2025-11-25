## Apache Iggy 서버 아키텍처 다이어그램 - 텍스트 추출

---

### 상단 (Server State)

**Server state** - 로그 형태의 상자들 (Latest command → "Create Stream")

**우측 설명:**
> All the commands, such as creating streams, deleting topics, modifying users permissions, etc. are appended to the server state log. Whenever the server starts, the log is loaded into memory, and all the entries are applied in the given order to recreate the current system state. Such an approach, allows implementing a fault-tolerant replication model.

---

### 중앙 좌측 (Streams 설명)

> Stream provides the physical & logical separation of its underlying topics. It can be thought of as the root level namespace, and depending on the use case, having multiple streams, could help with designing e.g. the multi-tenant solution, where data must be separated.

**구성요소:** Stream 1, Stream 2, Stream 3, Stream N

---

### 중앙 중간 (Topics 설명)

> Each stream may consist of multiple independent topics, and just like the stream itself, topic provides the grouping of underlying partitions which are the "unit of work". Topics might also have different permission rules. Additionally, topic is used for defining the server-side configuration for the allowed size, message expiry, cleanup policy etc.

**구성요소:** Topic 1, Topic 2, Topic 3, Topic N

---

### 중앙 우측 (Consumer Groups & Partitions 설명)

> The topic has 1 or more partitions, which allow to spread the workload across parallel producers and consumers. The particular partition of the data should be distributed evenly e.g. round robin or by using the consistent hashing based on the message key. The messages are handled with the usage of so called consumer groups.

**구성요소:** Consumer Groups → Partition 1, Partition 2, Partition N

---

### 우측 (Threads/Cores 설명)

> The data (partitions, in other words) must be distributed and pinned to the particular cores, in order to avoid lots of potential context switches due to the data being shared across the threads, via the so-ring synchronization.

> Any communication between the threads, should be based on the message passing. To ensure the fairness in the data distribution the consistent hashing can be used.

> The so-called shared nothing design, can significantly increase the performance and reliability of the overall system, (especially tail latencies), due to much more predictable usage of computing resources under the heavy load.

**구성요소:** Core #1 → Thread #1, Core #2 → Thread #2, Core #N → Thread #N

---

### 우측 하단 (Segments 설명)

> Segments are the actual files on disk storing the stream data as the append-only log. There might be multiple segments (e.g. split by 1GB of data), and only the last one is an active one. For each segment, there's an additional index file, allowing to quickly access the records by offset or timestamp. Only the closed segments can be deleted (e.g. based on the topic cleanup policy) or compacted. Each segment has its own file descriptor.

> The files (and network sockets) are read and written to using the io_uring (batching N calls into the single one, via the shared memory between the user space and kernel space) and directIO bypassing page cache with O_SYNC.

> Moreover, the zero-copy deserialization greatly improves the throughput and tail latencies due to avoiding the unnecessary memory of the data. Overall, the usage of computing resources is also significantly lower.

**구성요소:**
- Segment 1 (closed): 0 ~ 9999
- Segment 2 (closed): 10000 ~ 19999
- Segment N (active): 20000 ~ N (Latest message)

---

### 하단 (제목 및 특징)

**APACHE IGGY** (로고 포함)

**High-level architecture of the streaming layer for Iggy Server (WiP).**
**Extremely high throughput and low tail latencies are achieved with:**

- Shared-nothing architecture
- Zero-copy (de)serialization
- io_uring
- DirectIO

===

# 한국어 번역

## Apache Iggy 서버 아키텍처 다이어그램 - 한글 번역

---

### 상단 (서버 상태)

**Server state** - 최신 명령 → "Create Stream"

**우측 설명:**
> 스트림 생성, 토픽 삭제, 사용자 권한 수정 등 모든 명령은 서버 상태 로그에 추가된다. 서버가 시작될 때마다 로그가 메모리에 로드되고, 모든 항목이 주어진 순서대로 적용되어 현재 시스템 상태를 재구성한다. 이러한 접근 방식은 내결함성 복제 모델 구현을 가능하게 한다.

---

### 중앙 좌측 (스트림)

> 스트림은 하위 토픽들의 물리적 및 논리적 분리를 제공한다. 루트 레벨 네임스페이스로 생각할 수 있으며, 사용 사례에 따라 여러 스트림을 두면 데이터 분리가 필요한 멀티테넌트 솔루션 설계에 도움이 될 수 있다.

**구성요소:** Stream 1, Stream 2, Stream 3, Stream N

---

### 중앙 중간 (토픽)

> 각 스트림은 여러 개의 독립적인 토픽으로 구성될 수 있으며, 스트림과 마찬가지로 토픽은 "작업 단위"인 하위 파티션들의 그룹화를 제공한다. 토픽은 서로 다른 권한 규칙을 가질 수 있다. 또한 토픽은 허용 크기, 메시지 만료, 정리 정책 등 서버 측 설정을 정의하는 데 사용된다.

**구성요소:** Topic 1, Topic 2, Topic 3, Topic N

---

### 중앙 우측 (컨슈머 그룹 & 파티션)

> 토픽은 1개 이상의 파티션을 가지며, 이를 통해 병렬 프로듀서와 컨슈머 간에 워크로드를 분산할 수 있다. 특정 파티션의 데이터는 라운드 로빈 또는 메시지 키 기반 일관된 해싱을 사용하여 균등하게 분배되어야 한다. 메시지는 컨슈머 그룹을 통해 처리된다.

**구성요소:** Consumer Groups → Partition 1, Partition 2, Partition N

---

### 우측 (스레드/코어)

> 데이터(즉, 파티션)는 특정 코어에 분배 및 고정되어야 한다. 이는 io_uring 동기화를 통해 스레드 간 데이터 공유로 인한 잦은 컨텍스트 스위칭을 방지하기 위함이다.

> 스레드 간 모든 통신은 메시지 패싱 기반이어야 한다. 데이터 분배의 공정성을 보장하기 위해 일관된 해싱을 사용할 수 있다.

> 소위 "공유 없음(shared-nothing)" 설계는 전체 시스템의 성능과 안정성을 크게 향상시킬 수 있다(특히 테일 레이턴시). 이는 고부하 상황에서 컴퓨팅 리소스 사용이 훨씬 더 예측 가능하기 때문이다.

**구성요소:** Core #1 → Thread #1, Core #2 → Thread #2, Core #N → Thread #N

---

### 우측 하단 (세그먼트)

> 세그먼트는 스트림 데이터를 append-only 로그로 저장하는 실제 디스크 파일이다. 여러 세그먼트가 있을 수 있으며(예: 1GB 단위로 분할), 마지막 세그먼트만 활성 상태이다. 각 세그먼트에는 오프셋이나 타임스탬프로 레코드에 빠르게 접근할 수 있는 추가 인덱스 파일이 있다. 닫힌 세그먼트만 삭제(토픽 정리 정책 기반)하거나 압축할 수 있다. 각 세그먼트는 자체 파일 디스크립터를 가진다.

> 파일(및 네트워크 소켓)은 io_uring(사용자 공간과 커널 공간 간 공유 메모리를 통해 N개의 호출을 하나로 배칭)과 O_SYNC를 사용한 directIO(페이지 캐시 우회)를 사용하여 읽고 쓴다.

> 또한 제로카피 역직렬화는 불필요한 데이터 메모리 복사를 피함으로써 처리량과 테일 레이턴시를 크게 개선한다. 전반적으로 컴퓨팅 리소스 사용량도 상당히 낮아진다.

**구성요소:**
- Segment 1 (닫힘): 0 ~ 9999
- Segment 2 (닫힘): 10000 ~ 19999
- Segment N (활성): 20000 ~ N (최신 메시지)

---

### 하단 (제목 및 특징)

**APACHE IGGY**

**Iggy 서버 스트리밍 레이어의 고수준 아키텍처 (진행 중).**
**다음을 통해 극도로 높은 처리량과 낮은 테일 레이턴시 달성:**

- Shared-nothing 아키텍처
- 제로카피 (역)직렬화
- io_uring
- DirectIO
