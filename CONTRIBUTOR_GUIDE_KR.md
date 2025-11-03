# Apache Iggy 기여자 가이드 (한국어)

> **목표**: Apache Iggy 프로젝트의 Committer가 되기 위한 체계적인 학습 및 기여 가이드

## 목차

1. [시작하기](#1-시작하기)
2. [프로젝트 구조 이해](#2-프로젝트-구조-이해)
3. [핵심 개념과 아키텍처](#3-핵심-개념과-아키텍처)
4. [주요 모듈 심층 가이드](#4-주요-모듈-심층-가이드)
5. [코드 읽기 학습 경로](#5-코드-읽기-학습-경로)
6. [첫 기여하기](#6-첫-기여하기)
7. [Committer 로드맵](#7-committer-로드맵)
8. [학습 리소스](#8-학습-리소스)

---

## 1. 시작하기

### 1.1 개발 환경 설정

#### 필수 도구 설치

```bash
# Rust 설치 (rustup 사용)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 버전 확인
cargo version  # cargo 1.86.0 이상

# 프로젝트 클론
git clone https://github.com/apache/iggy.git
cd iggy

# 포크 추가 (기여를 위해)
git remote add myfork https://github.com/YOUR_USERNAME/iggy.git
```

#### 프로젝트 빌드

```bash
# 전체 프로젝트 빌드 (첫 빌드는 시간이 오래 걸립니다 - LTO 최적화 때문)
cargo build

# 릴리스 빌드
cargo build --release

# 테스트 실행
cargo test

# 특정 패키지만 테스트
cargo test -p server
```

#### 서버 실행

```bash
# 기본 실행 (개발 모드, 랜덤 root 패스워드 생성)
cargo run --bin iggy-server

# 개발용 기본 credentials 사용
cargo run --bin iggy-server -- --with-default-root-credentials
# username: iggy, password: iggy

# 환경 변수로 설정
export IGGY_ROOT_USERNAME=iggy
export IGGY_ROOT_PASSWORD=iggy
cargo run --bin iggy-server

# fresh start (데이터 삭제 후 시작)
cargo run --bin iggy-server -- --fresh
```

#### CLI 사용

```bash
# CLI 설치
cargo install iggy-cli

# 또는 프로젝트에서 직접 실행
cargo run --bin iggy -- --help

# 스트림 생성 예제
cargo run --bin iggy -- -u iggy -p iggy stream create dev
```

### 1.2 코드 스타일 및 컨벤션

```bash
# 코드 포맷팅 (기여 전 필수)
cargo fmt --all

# 린트 체크
cargo clippy --all-targets --all-features

# C# 포맷팅 (C# SDK 수정 시)
dotnet format
```

### 1.3 유용한 개발 도구

```bash
# 더 나은 에러 출력
cargo install cargo-expand

# 의존성 트리 확인
cargo tree -p server

# 상세 로그로 실행
RUST_LOG=trace cargo run --bin iggy-server

# tokio-console 사용 (async 디버깅)
# Cargo.toml에서 tokio-console feature 활성화 필요
```

---

## 2. 프로젝트 구조 이해

### 2.1 전체 디렉토리 구조

```
iggy/
├── core/                          # 핵심 Rust 구현
│   ├── server/                    # 메시지 스트리밍 서버 (메인)
│   ├── sdk/                       # Rust 클라이언트 SDK
│   ├── cli/                       # 인터랙티브 CLI
│   ├── common/                    # 공유 타입 및 유틸리티
│   ├── binary_protocol/           # 바이너리 프로토콜 정의
│   ├── bench/                     # 벤치마킹 도구
│   ├── connectors/                # 플러그인 시스템
│   │   ├── runtime/              # 커넥터 런타임
│   │   ├── sdk/                  # 커넥터 개발 SDK
│   │   ├── sources/              # 소스 커넥터
│   │   └── sinks/                # 싱크 커넥터
│   ├── ai/mcp/                    # Model Context Protocol 서버
│   ├── integration/               # 통합 테스트
│   └── tools/                     # 개발 도구
│
├── foreign/                       # 다국어 SDK
│   ├── go/
│   ├── csharp/
│   ├── java/
│   ├── python/
│   ├── node/
│   └── cpp/
│
├── examples/                      # 사용 예제
├── bdd/                          # BDD 테스트
├── web/                          # 웹 UI (SvelteKit)
├── scripts/                      # 빌드/테스트 스크립트
└── helm/                         # Kubernetes 배포
```

### 2.2 Cargo Workspace 구조

프로젝트는 **Cargo Workspace**로 구성되어 있습니다:

```toml
# 루트 Cargo.toml
[workspace]
members = [
    "core/server",
    "core/sdk",
    "core/cli",
    "core/common",
    # ... 모든 하위 크레이트
]
```

**주요 크레이트 간 관계**:
- `server` → `common`, `binary_protocol`, `sdk` 의존
- `sdk` → `common`, `binary_protocol` 의존
- `cli` → `sdk` 의존

### 2.3 서버 코드 구조 (`core/server/src/`)

```
server/src/
├── main.rs                       # 서버 진입점
├── lib.rs                        # 라이브러리 루트
│
├── streaming/                    # 핵심 스트리밍 로직
│   ├── systems/                  # System - 전역 상태 관리
│   │   └── system.rs            # System 구조체 (가장 중요!)
│   ├── streams/                  # Stream 관리
│   ├── topics/                   # Topic 관리
│   ├── partitions/               # Partition 관리
│   ├── segments/                 # Segment - 물리적 저장
│   ├── clients/                  # 클라이언트 연결 관리
│   ├── users/                    # 사용자 및 권한
│   ├── persistence/              # 영속화 레이어
│   └── utils/                    # 유틸리티 (MemoryPool 등)
│
├── tcp/                          # TCP 서버
├── quic/                         # QUIC 서버
├── http/                         # HTTP REST API
├── binary/                       # 바이너리 프로토콜 핸들러
│
├── state/                        # 시스템 상태 영속화
├── archiver/                     # 데이터 아카이빙 (S3/Disk)
├── channels/                     # 백그라운드 작업
├── configs/                      # 설정 관리
└── log/                          # 로깅
```

---

## 3. 핵심 개념과 아키텍처

### 3.1 데이터 모델 계층 구조

```
System (서버 전역 상태)
  └── Stream (멀티테넌트 격리 단위, ID: u32)
      └── Topic (메시지 카테고리, ID: u32)
          └── Partition (병렬 처리 단위, ID: u32)
              └── Segment (물리적 저장소, max 1 GiB)
                  ├── messages (바이너리 데이터)
                  ├── indexes (오프셋 인덱스)
                  └── time_indexes (타임스탬프 인덱스)
```

**파일 시스템 레이아웃**:
```
{system_path}/
└── streams/
    └── {stream_id}/
        └── topics/
            └── {topic_id}/
                └── partitions/
                    └── {partition_id}/
                        ├── 00000000000000000001 (segment)
                        ├── 00000000000000000001.index
                        ├── 00000000000000000001.timeindex
                        ├── 00000000000000000002
                        └── ...
```

### 3.2 핵심 개념

#### System (`streaming/systems/system.rs`)
- **서버의 전역 상태**를 관리하는 최상위 구조체
- `SharedSystem = Arc<RwLock<System>>` 패턴으로 스레드 안전성 보장
- 모든 스트림, 사용자, 클라이언트 연결을 관리

```rust
pub struct System {
    pub storage: Arc<SystemStorage>,
    pub streams: AHashMap<u32, Stream>,      // stream_id -> Stream
    pub streams_ids: AHashMap<String, u32>,  // stream_name -> stream_id
    pub users: AHashMap<UserId, User>,
    pub client_manager: IggySharedMut<ClientManager>,
    pub permissioner: Permissioner,
    pub metrics: Metrics,
    // ...
}
```

#### Stream (`streaming/streams/stream.rs`)
- 멀티테넌트 격리를 위한 최상위 네임스페이스
- 여러 Topic을 포함
- 각 Stream은 고유한 ID와 이름을 가짐

#### Topic (`streaming/topics/topic.rs`)
- 메시지 카테고리/채널
- 여러 Partition으로 구성
- 압축, 메시지 만료 정책 설정 가능

#### Partition (`streaming/partitions/partition.rs`)
- 병렬 처리를 위한 물리적 분할 단위
- 독립적으로 읽기/쓰기 가능
- 여러 Segment로 구성

#### Segment (`streaming/segments/segment.rs`)
- 실제 메시지가 저장되는 물리적 파일
- Append-only 로그 구조
- 최대 크기: 1 GiB (설정 가능)
- 구성 요소:
  - **메시지 파일**: 실제 바이너리 데이터
  - **인덱스 파일**: 오프셋 → 파일 위치 매핑
  - **시간 인덱스 파일**: 타임스탬프 → 오프셋 매핑

### 3.3 메시지 흐름

#### 쓰기 경로 (Producer)
```
클라이언트 → TCP/QUIC/HTTP → 바이너리 핸들러
                                ↓
                      System::append_messages()
                                ↓
                      Stream::append_messages()
                                ↓
                      Topic::append_messages()
                                ↓
                    Partition::append_messages()
                                ↓
                  현재 Segment에 append (또는 새 Segment 생성)
                                ↓
                          인덱스 업데이트
                                ↓
                          fsync (설정에 따라)
```

#### 읽기 경로 (Consumer)
```
클라이언트 → TCP/QUIC/HTTP → 바이너리 핸들러
                                ↓
                      System::poll_messages()
                                ↓
                    Stream/Topic/Partition 탐색
                                ↓
                Segment에서 인덱스를 사용하여 메시지 찾기
                                ↓
                    제로카피 역직렬화
                                ↓
                      클라이언트에 반환
```

### 3.4 주요 성능 최적화 기법

1. **제로카피 직렬화/역직렬화**
   - `postcard` 크레이트 사용
   - 메모리 복사 최소화

2. **메모리 풀링** (`streaming/utils/memory_pool.rs`)
   - 메시지 배치 버퍼 재사용
   - 기본 4 GiB 풀

3. **인덱스 기반 조회**
   - 오프셋 인덱스: O(log n) 조회
   - 시간 인덱스: 타임스탬프 기반 조회

4. **비동기 I/O** (Tokio)
   - 모든 I/O 작업은 비동기
   - 동시성 극대화

5. **Direct I/O** (선택적)
   - OS 캐시 우회
   - 예측 가능한 성능

6. **AHashMap** (ahash)
   - `HashMap`보다 빠른 해시맵
   - DoS 공격 방지

---

## 4. 주요 모듈 심층 가이드

### 4.1 `streaming/systems/system.rs` - 핵심 모듈

**역할**: 서버의 모든 상태와 비즈니스 로직의 중심

**주요 메서드**:
```rust
impl System {
    // 초기화
    pub async fn init(&mut self) -> Result<()>
    pub async fn shutdown(&mut self) -> Result<()>

    // Stream 관리
    pub async fn create_stream(&mut self, ...) -> Result<()>
    pub async fn get_stream(&self, stream_id: &StreamId) -> Result<&Stream>

    // 메시지 작업
    pub async fn append_messages(&self, ...) -> Result<()>
    pub async fn poll_messages(&self, ...) -> Result<PolledMessages>

    // 사용자 관리
    pub async fn login_user(&mut self, ...) -> Result<Session>
    pub async fn create_user(&mut self, ...) -> Result<()>
}
```

**읽기 가이드**:
1. `System` 구조체 정의 이해
2. `init()` 메서드 - 서버 시작 시 무엇을 하는지
3. `append_messages()` - 메시지 쓰기 경로
4. `poll_messages()` - 메시지 읽기 경로

### 4.2 `streaming/segments/segment.rs` - 저장소 핵심

**역할**: 실제 메시지를 디스크에 저장하고 읽는 핵심 로직

**주요 구조체**:
```rust
pub struct Segment {
    pub start_offset: u64,
    pub current_offset: u64,
    pub current_size_bytes: u64,
    pub max_size_bytes: u64,
    messages_path: String,
    index_path: String,
    time_index_path: String,
    // ...
}
```

**주요 메서드**:
- `append_batch()`: 메시지 배치 추가
- `get_messages()`: 메시지 조회
- `flush()`: 디스크에 동기화

**학습 포인트**:
- Append-only 로그 구현 방식
- 인덱싱 전략
- 파일 I/O 최적화

### 4.3 `binary/handlers/` - 프로토콜 핸들러

**역할**: 클라이언트 요청을 처리하는 핸들러 구현

**구조**:
```
binary/handlers/
├── streams/
│   ├── create_stream_handler.rs
│   ├── get_stream_handler.rs
│   └── ...
├── topics/
├── messages/
│   ├── send_messages_handler.rs
│   ├── poll_messages_handler.rs
│   └── ...
└── users/
```

**패턴**:
```rust
pub async fn handle(
    command: CreateStream,
    sender: &mut impl Sender,
    session: &Session,
    system: &SharedSystem,
) -> Result<(), IggyError> {
    // 1. 권한 확인
    // 2. 입력 검증
    // 3. 비즈니스 로직 실행 (System 메서드 호출)
    // 4. 응답 전송
}
```

**학습 포인트**:
- 커맨드 패턴 구현
- 권한 확인 방식
- 에러 처리

### 4.4 `tcp/tcp_server.rs` - TCP 서버

**역할**: TCP 연결 관리 및 바이너리 프로토콜 처리

**주요 흐름**:
1. TCP 연결 수신 (`TcpListener`)
2. 각 연결을 독립적인 Tokio 태스크로 처리
3. 바이너리 프로토콜 파싱
4. 핸들러에 위임
5. 응답 전송

**학습 포인트**:
- Tokio TCP 서버 구현
- 커스텀 바이너리 프로토콜 파싱
- 커넥션 풀링

### 4.5 `http/` - REST API

**역할**: HTTP REST API 제공 (Axum 기반)

**주요 파일**:
- `http_server.rs`: HTTP 서버 초기화
- `state.rs`: HTTP 핸들러 공유 상태
- `mapper.rs`: HTTP 요청/응답 ↔ 내부 커맨드 매핑
- 각 리소스별 핸들러

**학습 포인트**:
- Axum 웹 프레임워크
- REST API 설계
- 내부 바이너리 프로토콜과의 통합

### 4.6 `streaming/users/permissioner.rs` - 권한 관리

**역할**: 세분화된 권한 체크

**권한 종류**:
- Global: 전역 권한 (서버 관리)
- Stream: 스트림별 권한
- Topic: 토픽별 권한

**학습 포인트**:
- RBAC (Role-Based Access Control) 구현
- 권한 상속 및 전파

### 4.7 `channels/` - 백그라운드 작업

**역할**: 주기적인 백그라운드 태스크 실행

**주요 작업**:
- `SaveMessagesExecutor`: 메시지 저장
- `MaintainMessagesExecutor`: 메시지 만료/정리
- `ArchiveStateExecutor`: 상태 아카이빙
- `VerifyHeartbeatsExecutor`: 클라이언트 헬스체크

**패턴**: Command 패턴
```rust
pub trait ServerCommand {
    async fn execute(&mut self, system: &SharedSystem) -> Result<()>;
}
```

---

## 5. 코드 읽기 학습 경로

초보자가 코드를 이해하기 위한 **추천 학습 순서**입니다.

### 단계 1: 진입점 및 초기화 (1-2일)

1. **`core/server/src/main.rs`** (200줄)
   - 서버가 어떻게 시작되는지 이해
   - 설정 로딩
   - TCP/QUIC/HTTP 서버 시작
   - System 초기화

2. **`core/server/src/streaming/systems/system.rs`** - `System::new()`, `init()`
   - System 구조체의 필드들
   - 초기화 과정
   - 영속화된 데이터 로딩

3. **`core/server/src/configs/server.rs`**
   - 서버 설정 구조 이해

### 단계 2: 데이터 모델 이해 (2-3일)

4. **`core/server/src/streaming/streams/stream.rs`**
   - Stream 구조체와 메서드

5. **`core/server/src/streaming/topics/topic.rs`**
   - Topic 구조체와 메서드

6. **`core/server/src/streaming/partitions/partition.rs`**
   - Partition 구조체와 메서드

7. **`core/server/src/streaming/segments/segment.rs`**
   - Segment 구조체 (가장 중요!)
   - `append_batch()` 메서드
   - `get_messages()` 메서드

### 단계 3: 메시지 쓰기 경로 (2-3일)

8. **`core/binary_protocol/src/commands/messages/send_messages.rs`**
   - SendMessages 커맨드 구조

9. **`core/server/src/binary/handlers/messages/send_messages_handler.rs`**
   - 메시지 전송 핸들러

10. **`System::append_messages()` 메서드**
    - 전체 쓰기 경로 추적
    - Stream → Topic → Partition → Segment

### 단계 4: 메시지 읽기 경로 (2-3일)

11. **`core/binary_protocol/src/commands/messages/poll_messages.rs`**
    - PollMessages 커맨드 구조
    - 다양한 폴링 전략

12. **`core/server/src/binary/handlers/messages/poll_messages_handler.rs`**
    - 메시지 폴링 핸들러

13. **`System::poll_messages()` 메서드**
    - 전체 읽기 경로 추적

### 단계 5: 네트워크 레이어 (2-3일)

14. **`core/server/src/tcp/tcp_server.rs`**
    - TCP 서버 구현
    - 연결 처리

15. **`core/server/src/quic/quic_server.rs`**
    - QUIC 서버 구현

16. **`core/server/src/http/http_server.rs`**
    - HTTP REST API 서버

### 단계 6: 고급 기능 (필요시)

17. **Consumer Groups** (`streaming/consumer_groups/`)
18. **Deduplication** (`streaming/deduplication/`)
19. **Archiving** (`archiver/`)
20. **Connectors** (`core/connectors/`)

### 학습 팁

- **디버거 사용**: VS Code + rust-analyzer + CodeLLDB
- **로그 추적**: `RUST_LOG=trace` 로 실행하고 로그를 읽으며 코드 흐름 이해
- **테스트 코드 읽기**: 각 모듈의 `#[cfg(test)]` 섹션
- **예제 실행**: `examples/rust/` 의 예제들을 실행하며 이해
- **브레이크포인트**: 핵심 메서드에 브레이크포인트를 걸고 변수 상태 확인

---

## 6. 첫 기여하기

### 6.1 기여 프로세스

```bash
# 1. 이슈 찾기 또는 생성
# https://github.com/apache/iggy/issues

# 2. 브랜치 생성
git checkout -b fix/my-fix-description

# 3. 코드 수정

# 4. 테스트 실행
cargo test
cargo fmt --all
cargo clippy --all-targets --all-features

# 5. 커밋 (Conventional Commits 형식)
git commit -m "fix(server): fix memory leak in segment cleanup"

# 6. 푸시
git push myfork fix/my-fix-description

# 7. Pull Request 생성
# PR 제목은 Conventional Commits 형식을 따라야 함
# 예: "fix(server): fix memory leak in segment cleanup"
```

### 6.2 Conventional Commits 형식

PR 제목은 다음 형식을 따라야 합니다:

```
<type>(<scope>): <description>

예시:
fix(server): fix memory leak in segment cleanup
feat(sdk): add support for batch message sending
refactor(tcp): improve connection pooling
docs(readme): update installation instructions
test(integration): add tests for consumer groups
chore(deps): update dependencies
```

**주요 타입**:
- `feat`: 새로운 기능
- `fix`: 버그 수정
- `refactor`: 리팩토링
- `docs`: 문서 수정
- `test`: 테스트 추가/수정
- `chore`: 빌드, 의존성 등
- `perf`: 성능 개선

**주요 스코프**:
- `server`, `sdk`, `cli`, `tcp`, `quic`, `http`, `streaming`, etc.

### 6.3 Good First Issues 찾기

**추천 시작점**:

1. **문서 개선**
   - 오타 수정
   - 예제 추가
   - 주석 개선
   - 번역

2. **테스트 추가**
   - 커버리지가 낮은 부분 찾기
   - 엣지 케이스 테스트 추가

3. **작은 버그 수정**
   - GitHub Issues에서 `good first issue` 라벨 찾기
   - 간단한 로직 버그

4. **로깅/에러 메시지 개선**
   - 더 명확한 에러 메시지
   - 추가적인 trace 로그

5. **코드 품질 개선**
   - Clippy 경고 수정
   - 코드 중복 제거
   - 타입 안전성 개선

**이슈 찾는 법**:
```bash
# GitHub에서:
label:good-first-issue is:open is:issue

# 또는 Discord에서 질문:
https://discord.gg/C5Sux5NcRa
```

### 6.4 기여 체크리스트

PR을 제출하기 전에 확인:

- [ ] 이슈가 존재하거나 생성했나?
- [ ] 브랜치 이름이 설명적인가?
- [ ] 모든 테스트가 통과하나? (`cargo test`)
- [ ] 코드가 포맷팅되었나? (`cargo fmt --all`)
- [ ] Clippy 경고가 없나? (`cargo clippy --all-targets`)
- [ ] 새로운 기능에 테스트를 추가했나?
- [ ] PR 제목이 Conventional Commits 형식인가?
- [ ] PR 설명이 변경사항을 명확히 설명하나?
- [ ] Apache 라이선스 헤더가 모든 새 파일에 있나?

---

## 7. Committer 로드맵

### 7.1 Apache Committer란?

**Committer**:
- 프로젝트에 직접 코드를 커밋할 수 있는 권한
- 다른 기여자의 PR을 리뷰하고 머지할 수 있음
- 프로젝트 방향성 결정에 참여
- Apache Software Foundation의 공식 인정

### 7.2 Committer가 되기 위한 단계별 로드맵

#### Phase 1: 초기 기여 (1-3개월)

**목표**: 프로젝트 이해 및 첫 기여

- [ ] 프로젝트 코드베이스 숙지
- [ ] Discord 커뮤니티 참여
- [ ] 3-5개의 작은 PR 머지
  - 문서 개선
  - 테스트 추가
  - 작은 버그 수정

**성과 지표**:
- 최소 3개의 머지된 PR
- 코드 리뷰 참여
- 커뮤니티 활동

#### Phase 2: 중급 기여 (3-6개월)

**목표**: 중요한 기능 구현 및 버그 수정

- [ ] 중간 규모 기능 구현 (2-3개)
- [ ] 중요한 버그 수정
- [ ] 다른 기여자의 PR 리뷰
- [ ] GitHub Discussions/Issues에서 질문 답변
- [ ] 디자인 논의 참여

**추천 기여 영역**:
- 새로운 프로토콜 최적화
- 성능 개선
- 새로운 SDK 기능
- 커넥터 개발
- 벤치마킹 개선

**성과 지표**:
- 10개 이상의 머지된 PR
- 5개 이상의 의미있는 코드 리뷰
- 커뮤니티에서 인정받는 기술적 의견

#### Phase 3: 고급 기여 (6-12개월)

**목표**: 프로젝트의 핵심 기여자가 되기

- [ ] 주요 기능 설계 및 구현
  - 새로운 스토리지 최적화
  - 클러스터링 기능 (로드맵)
  - io_uring 지원 (로드맵)
- [ ] 아키텍처 개선 제안
- [ ] 다른 기여자 멘토링
- [ ] 릴리스 노트 작성 참여
- [ ] 문서 전반 개선

**성과 지표**:
- 20개 이상의 의미있는 PR
- 다수의 디자인 제안 및 RFC
- 커뮤니티 리더십
- 지속적인 활동 (최소 6개월)

#### Phase 4: Committer 후보 (12개월+)

**지표**:
- 지속적인 고품질 기여
- 커뮤니티 신뢰 구축
- 프로젝트 이해도 입증
- 다른 Committer들의 추천

**Committer 지명 프로세스**:
1. 기존 Committer가 후보를 제안
2. 프라이빗 메일링 리스트에서 논의
3. 투표 (Lazy Consensus)
4. 승인 시 초대

### 7.3 주요 포커스 영역 (차별화 전략)

Committer가 되기 위해서는 특정 영역에서 전문성을 보이는 것이 유리합니다:

#### 옵션 1: 성능 및 최적화
- 벤치마킹 개선
- 프로파일링 및 병목지점 발견
- 메모리/CPU 최적화
- io_uring 구현 기여

#### 옵션 2: 새로운 기능
- 새로운 SDK 언어 지원 (C++, Elixir)
- 커넥터 생태계 확장
- 새로운 프로토콜 기능

#### 옵션 3: 안정성 및 테스트
- 테스트 커버리지 향상
- 엣지 케이스 발견 및 수정
- Integration/E2E 테스트 개선
- Chaos engineering

#### 옵션 4: 개발자 경험
- CLI 기능 개선
- Web UI 기능 추가
- 문서 및 예제 대폭 개선
- 디버깅 도구

#### 옵션 5: 클러스터링 (로드맵)
- VSR (Viewstamped Replication) 구현
- 리더 선출
- 데이터 복제

### 7.4 커뮤니티 활동

**중요도 높음**:
- Discord 활발히 참여
- GitHub Issues/Discussions 답변
- PR 리뷰 (타인의 PR에 건설적인 피드백)
- 디자인 논의 참여
- 블로그 포스트 작성 (개인 또는 공식)

**네트워킹**:
- 기존 Committer들과 소통
- 정기적으로 의견 교환
- 존중과 협력의 태도

---

## 8. 학습 리소스

### 8.1 프로젝트 리소스

**공식 문서**:
- 웹사이트: https://iggy.apache.org
- 문서: https://iggy.apache.org/docs/
- 블로그: https://iggy.apache.org/blogs/

**커뮤니티**:
- Discord: https://discord.gg/C5Sux5NcRa (가장 활발)
- GitHub Discussions: https://github.com/apache/iggy/discussions
- GitHub Issues: https://github.com/apache/iggy/issues

**벤치마킹**:
- 벤치마크 플랫폼: https://benchmarks.iggy.apache.org
- 벤치마크 블로그: https://iggy.apache.org/blogs/2025/02/17/transparent-benchmarks

**예제 코드**:
- `examples/rust/`: Rust 예제
- `examples/go/`, `examples/python/`: 다른 언어 예제
- BDD 테스트: `bdd/scenarios/`: 실제 사용 시나리오

### 8.2 Rust 학습 리소스

**기본**:
- The Rust Programming Language (공식 책): https://doc.rust-lang.org/book/
- Rust by Example: https://doc.rust-lang.org/rust-by-example/

**비동기 프로그래밍**:
- Tokio 튜토리얼: https://tokio.rs/tokio/tutorial
- Async Book: https://rust-lang.github.io/async-book/

**고급**:
- The Rustonomicon: https://doc.rust-lang.org/nomicon/ (unsafe Rust)
- Rust Performance Book: https://nnethercote.github.io/perf-book/

### 8.3 메시지 스트리밍 개념

**핵심 논문**:
- Kafka 논문: "Kafka: a Distributed Messaging System for Log Processing"
- Viewstamped Replication: http://pmg.csail.mit.edu/papers/vr-revisited.pdf
- Log-structured Storage: https://www.cs.umb.edu/~poneil/lsmtree.pdf

**비교 대상 시스템**:
- Apache Kafka
- Apache Pulsar
- NATS Streaming
- RedPanda

### 8.4 개발 도구

**필수 VS Code 익스텐션**:
- rust-analyzer: Rust LSP
- CodeLLDB: 디버깅
- Better TOML: 설정 파일
- REST Client: HTTP API 테스트 (`server.http` 파일용)

**유용한 CLI 도구**:
```bash
# 코드 탐색
cargo install cargo-modules  # 모듈 트리 보기
cargo install cargo-bloat    # 바이너리 크기 분석

# 성능
cargo install cargo-flamegraph  # 프로파일링
cargo install cargo-criterion   # 벤치마킹

# 테스트
cargo install cargo-nextest  # 빠른 테스트 러너
cargo install cargo-tarpaulin  # 커버리지
```

### 8.5 학습 스케줄 예시 (3개월)

#### Week 1-2: 환경 설정 및 이해
- [ ] 개발 환경 완벽 설정
- [ ] 프로젝트 빌드 및 실행
- [ ] CLI로 기본 작업 해보기
- [ ] 이 가이드 완독
- [ ] Discord 가입, 자기소개

#### Week 3-4: 코드 읽기 (Phase 1)
- [ ] main.rs → System 초기화 흐름 이해
- [ ] 데이터 모델 코드 읽기
- [ ] 간단한 예제 실행 및 디버깅

#### Week 5-6: 코드 읽기 (Phase 2)
- [ ] 메시지 쓰기 경로 완전 이해
- [ ] 메시지 읽기 경로 완전 이해
- [ ] 테스트 코드 읽기

#### Week 7-8: 첫 기여
- [ ] Good first issue 찾기
- [ ] 첫 PR 제출
- [ ] 코드 리뷰 피드백 반영
- [ ] 머지 축하! 🎉

#### Week 9-10: 지속적인 기여
- [ ] 2-3개의 추가 PR
- [ ] 다른 사람의 PR 리뷰 시작
- [ ] 더 복잡한 이슈 도전

#### Week 11-12: 전문성 구축
- [ ] 특정 영역 선택 (위의 5가지 옵션 중)
- [ ] 중간 규모 기능 계획
- [ ] 디자인 제안 작성
- [ ] RFC 또는 Discussion 시작

---

## 부록 A: 자주 사용하는 명령어

```bash
# 개발
cargo run --bin iggy-server -- --with-default-root-credentials --fresh
cargo run --bin iggy -- -u iggy -p iggy stream list
RUST_LOG=trace cargo run --bin iggy-server 2>&1 | grep "append_messages"

# 테스트
cargo test --lib                    # 라이브러리 테스트만
cargo test --test integration       # 통합 테스트
cargo test test_name -- --nocapture # 특정 테스트, 출력 보기

# 코드 품질
cargo fmt --all --check            # 포맷 체크 (CI용)
cargo clippy --all-targets -- -D warnings  # 경고를 에러로

# 빌드 최적화
cargo build --release              # 릴리스 빌드
RUSTFLAGS="-C target-cpu=native" cargo build --release  # 네이티브 최적화

# 의존성
cargo tree -p server -i tokio      # tokio를 의존하는 경로
cargo outdated                      # 오래된 의존성 확인
```

## 부록 B: 유용한 디버깅 팁

```rust
// 1. 구조체 출력
dbg!(&my_struct);

// 2. 특정 모듈만 로그
RUST_LOG=server::streaming::segments=trace cargo run

// 3. 테스트 중 로그 보기
RUST_LOG=debug cargo test test_name -- --nocapture

// 4. tokio-console (async 태스크 디버깅)
// Cargo.toml에서 feature 활성화 후:
console-subscriber = "0.4"
tokio-console  # 별도 터미널에서 실행
```

## 부록 C: 참고할 만한 과거 PR

**좋은 첫 PR 예시** (실제 프로젝트에서 찾기):
- 문서 오타 수정
- 테스트 추가
- 로그 메시지 개선
- 작은 리팩토링

**중급 PR 예시**:
- 새로운 CLI 명령어 추가
- HTTP 엔드포인트 추가
- 성능 최적화
- 새로운 커넥터

---

## 결론

Apache Iggy는 야심찬 프로젝트이며, **고품질 기여를 지속적으로 하면 Committer가 될 수 있습니다**.

**핵심 요점**:
1. **꾸준함**: 일회성이 아닌 지속적인 기여
2. **품질**: 적은 수의 고품질 PR이 많은 저품질 PR보다 낫습니다
3. **커뮤니티**: 코드만이 아니라 커뮤니티 참여도 중요
4. **전문성**: 특정 영역에서 깊은 이해를 보이기
5. **협력**: 다른 기여자들과 긍정적으로 협력

**첫 단계**:
1. Discord에 가입하고 자기소개
2. 이 가이드를 따라 환경 설정
3. 코드 읽기 시작
4. 첫 PR 제출

화이팅! 질문이 있으면 Discord에서 언제든지 물어보세요! 🚀

---

**작성자**: Claude (Assistant)
**최종 업데이트**: 2025-10-31
**대상**: Rust 기본 문법을 아는 한국어 사용자
**피드백**: 이 가이드에 대한 피드백은 GitHub Issues 또는 Discord에서 환영합니다!
