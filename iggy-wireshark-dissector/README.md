# Iggy Wireshark Dissector (Simple Version)

Iggy 프로토콜을 분석하기 위한 Wireshark Dissector입니다. 현재는 가장 간단한 두 가지 명령어만 지원합니다:
- **PING** (code: 1)
- **GET_STATS** (code: 10)

## 프로토콜 구조

### Request 구조
```
+-----------------------------------------------------------+
|           |           |                                   |
|  LENGTH   |   CODE    |              PAYLOAD              |
|           |           |                                   |
+-----------------------------------------------------------+
|  4 bytes  |  4 bytes  |              N bytes              |
```

- **LENGTH**: 4-byte integer (u32, little-endian) = CODE (4 bytes) + PAYLOAD (N bytes)
- **CODE**: 4-byte integer (u32, little-endian) - 명령어 코드
- **PAYLOAD**: 명령어별 데이터 (PING과 GET_STATS는 비어있음)

### 지원하는 명령어

#### PING (code: 1)
- Payload: 없음
- 전체 패킷: 8 bytes
- Hex: `04 00 00 00 01 00 00 00`

#### GET_STATS (code: 10)
- Payload: 없음
- 전체 패킷: 8 bytes
- Hex: `04 00 00 00 0a 00 00 00`

## 설치 방법

### 1. Lua Dissector 설치

```bash
# Wireshark 플러그인 디렉토리 생성
mkdir -p ~/.local/lib/wireshark/plugins/

# Dissector 복사
cp iggy_simple.lua ~/.local/lib/wireshark/plugins/

# 또는 심볼릭 링크 생성 (개발 중)
ln -s $(pwd)/iggy_simple.lua ~/.local/lib/wireshark/plugins/
```

### 2. Wireshark/tshark 재시작

플러그인을 설치한 후 Wireshark나 tshark를 재시작하세요.

## 사전 준비

### tshark 설치

통합 테스트를 실행하려면 tshark (Wireshark CLI)가 필요합니다:

```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt-get install tshark

# 설치 확인
tshark --version
```

## 테스트 방법

### 방법 1: 통합 테스트 (권장)

실제 tshark를 실행하여 dissector가 올바르게 작동하는지 자동으로 검증합니다:

```bash
# 통합 테스트 실행 (tshark 필요)
cargo test -p iggy-wireshark-dissector --test integration_test -- --ignored --nocapture
```

이 테스트는:
- ✅ tshark를 자동으로 실행하고 live capture 모드로 패킷 캡처
- ✅ Dummy TCP 서버를 시작하여 패킷 수신
- ✅ PING과 GET_STATS 패킷을 전송
- ✅ tshark의 JSON 출력을 파싱하여 dissection 결과 검증
- ✅ LENGTH, CODE, Command Name 필드가 올바르게 파싱되었는지 확인

### 방법 2: 수동 테스트 (실제 Iggy 서버)

1. **Iggy 서버 시작**
```bash
cargo run --bin server
```

2. **tshark로 패킷 캡처 시작** (새 터미널)
```bash
tshark -i lo0 -f "tcp port 8090" -Y iggy -V
```

3. **테스트 클라이언트 실행** (새 터미널)
```bash
cargo run -p iggy-wireshark-dissector
```

### 방법 3: Wireshark GUI로 테스트

1. Wireshark 실행
2. Loopback interface (lo0) 캡처 시작
3. Display filter: `iggy`
4. Capture filter: `tcp port 8090`
5. 테스트 프로그램 또는 실제 Iggy 클라이언트 실행

## 예상 출력

### tshark 출력 예시
```
Frame 1: 62 bytes on wire (496 bits), 62 bytes captured (496 bits) on interface lo0, id 0
Iggy Protocol Data
    Length: 4
    Command Code: 1
    Command Name: Ping
```

### 통합 테스트 출력 예시
```
running 2 tests
test test_ping_dissection_with_tshark ... ✓ PING dissection verified successfully!
ok
test test_get_stats_dissection_with_tshark ... ✓ GET_STATS dissection verified successfully!
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 테스트 프로그램 출력 예시
```
=== Iggy Wireshark Dissector Test ===

Sending PING command:
  LENGTH: 4 (0x04 0x00 0x00 0x00)
  CODE: 1 (0x01 0x00 0x00 0x00)
  Hex: 0400000001000000

Sending GET_STATS command:
  LENGTH: 4 (0x04 0x00 0x00 0x00)
  CODE: 10 (0x0a 0x00 0x00 0x00)
  Hex: 040000000a000000
```

## 개발 노트

### 현재 구현 상태
- ✅ PING 명령어 dissection
- ✅ GET_STATS 명령어 dissection
- ✅ 기본 프로토콜 구조 파싱
- ✅ tshark를 이용한 자동화된 통합 테스트
- ✅ 테스트 프로그램

### TODO (향후 작업)
- [ ] 더 많은 명령어 지원 (LoginUser, CreateStream 등)
- [ ] Response 메시지 파싱 추가
- [ ] 공통 데이터 타입 (Identifier, Consumer 등) 파서
- [ ] TCP 세그먼트 재조립 지원
- [ ] PCAP 파일 기반 regression 테스트

## 참고 자료

- Iggy 프로토콜 문서: https://iggy.apache.org/docs/server/schema/
- 코드 위치:
  - 명령어 코드: `core/common/src/types/command/mod.rs`
  - 바이너리 구현: `core/server/src/binary/command.rs`
  - PING 구현: `core/common/src/commands/system/ping.rs`
  - GET_STATS 구현: `core/common/src/commands/system/get_stats.rs`

## 문제 해결

### Dissector가 로드되지 않는 경우

1. 플러그인 경로 확인:
```bash
tshark -G folders | grep plugins
```

2. Lua 플러그인이 활성화되어 있는지 확인:
```bash
tshark -G plugins | grep -i lua
```

3. Lua 문법 오류 확인:
```bash
lua iggy_simple.lua
```

### 패킷이 캡처되지 않는 경우

1. 올바른 인터페이스 사용 확인 (macOS: `lo0`, Linux: `lo`)
2. 포트 번호 확인 (기본: 8090)
3. 캡처 권한 확인 (sudo가 필요할 수 있음)
