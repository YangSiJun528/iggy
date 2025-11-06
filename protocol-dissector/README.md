# Iggy Protocol Dissector

Wireshark Lua 기반 Dissector로 iggy 프로토콜의 바이너리 통신(TCP/QUIC) 데이터를 분석합니다.

## 개요

이 프로젝트는 iggy 프로토콜의 바이너리 메시지를 Wireshark에서 사람이 읽기 쉽게 파싱하는 Lua dissector를 제공합니다. 초기 구현으로 다음 명령어를 지원합니다:

- **Ping** (code: 1) - payload 없음
- **GetStats** (code: 10) - payload 없음
- **LoginUser** (code: 38) - username, password, version, context를 포함하는 payload
- **StoreConsumerOffset** (code: 121) - consumer, stream_id, topic_id, partition_id, offset (공통 데이터 타입 사용 예시)

## 프로토콜 구조

### Request
| 필드 | 크기 | 설명 |
|------|------|------|
| length | 4 bytes (u32 LE) | 전체 길이 = code(4) + payload(N) |
| code | 4 bytes (u32 LE) | 요청 코드 |
| payload | N bytes | 실제 데이터 |

### Response
| 필드 | 크기 | 설명 |
|------|------|------|
| status | 4 bytes (u32 LE) | 상태 코드 (0: 성공, 그 외: 오류) |
| length | 4 bytes (u32 LE) | 전체 길이 = status(4) + payload(N) |
| payload | N bytes | 응답 데이터 |

## 설치 및 사용

### 필수 요구사항

- Wireshark 및 tshark 설치
- Rust 툴체인 (테스트 실행 시)

### Wireshark에서 Dissector 사용

1. Lua 스크립트를 Wireshark의 플러그인 디렉토리에 복사:
   ```bash
   # macOS
   cp iggy_dissector.lua ~/.local/lib/wireshark/plugins/
   rm ~/.local/lib/wireshark/plugins/iggy_dissector.lua

   # Linux
   cp iggy_dissector.lua ~/.local/lib/wireshark/plugins/
   rm ~/.local/lib/wireshark/plugins/iggy_dissector.lua

   # Windows
   copy iggy_dissector.lua %APPDATA%\Wireshark\plugins\
   ```

2. 또는 Wireshark에서 직접 로드:
   - Wireshark 실행
   - Analyze > Reload Lua Plugins
   - 또는 `-X lua_script:iggy_dissector.lua` 옵션으로 시작

3. Heuristic dissector로 동작하므로 TCP 트래픽을 캡처하면 자동으로 Iggy 프로토콜을 감지하고 파싱합니다.
   - 포트 번호에 관계없이 패킷 내용을 분석하여 Iggy 프로토콜인지 판단
   - 알려진 command code나 status code 패턴으로 자동 인식

### 테스트 실행

테스트는 `tshark`를 사용하여 자동으로 패킷을 캡처하고 dissector를 검증합니다.

```bash
cd protocol-dissector

# 모든 테스트 실행 (ignored 테스트 포함)
cargo test -- --ignored --nocapture

# 특정 테스트 실행
cargo test test_ping_dissection_with_tshark -- --ignored --nocapture
cargo test test_get_stats_dissection_with_tshark -- --ignored --nocapture
cargo test test_login_user_dissection_with_tshark -- --ignored --nocapture
cargo test test_store_consumer_offset_dissection_with_tshark -- --ignored --nocapture
```

**참고**: 테스트는 시스템에 `tshark`가 설치되어 있어야 하며, 로컬 네트워크 인터페이스(lo0)에 대한 캡처 권한이 필요합니다.

## 지원하는 명령어

현재 구현된 명령어:

| Code | 명령어 | Payload |
|------|--------|---------|
| 1 | Ping | 없음 |
| 10 | GetStats | 없음 |
| 38 | LoginUser | username, password, version, context |
| 121 | StoreConsumerOffset | consumer, stream_id, topic_id, partition_id, offset |

## 공통 데이터 타입

Dissector는 재사용 가능한 공통 데이터 타입을 지원합니다:

### Identifier
- **구조**: kind (1 byte) + length (1 byte) + value (length bytes)
- **Kind 타입**:
  - 1 = Numeric (u32 little-endian, length = 4)
  - 2 = String (UTF-8, length = 문자열 길이)
- **사용처**: stream ID, topic ID, consumer ID 등

### Consumer
- **구조**: kind (1 byte) + Identifier
- **Kind 타입**:
  - 1 = Consumer (일반 consumer)
  - 2 = ConsumerGroup (consumer group)
- **사용처**: consumer offset 관련 명령어

## 확장성

Lua 스크립트는 모듈화되어 있어 새로운 명령어를 쉽게 추가할 수 있습니다.

### 새 명령어 추가하기

`commands` 테이블에 새 항목을 추가하면 됩니다:

```lua
[NEW_CODE] = {
    name = "NewCommand",
    fields = {
        -- 명령어 전용 ProtoField 정의
        my_field = ProtoField.uint32("iggy.newcmd.my_field", "My Field", base.DEC),
        my_count = ProtoField.uint64("iggy.newcmd.my_count", "My Count", base.DEC),
    },
    dissect_payload = function(self, tvbuf, payload_tree, offset, payload_len)
        local pktlen = offset + payload_len

        -- 기본 타입 헬퍼 함수 사용
        offset = dissect_u32_le(tvbuf, payload_tree, offset, self.fields.my_field, pktlen)
        if not offset then return end

        offset = dissect_u64_le(tvbuf, payload_tree, offset, self.fields.my_count, pktlen)
        if not offset then return end

        -- 공통 데이터 타입 사용
        offset, _ = dissect_identifier(tvbuf, payload_tree, offset, "Resource ID")
        if not offset then return end
    end,
}
```

### 공통 데이터 타입 사용하기

공통 데이터 타입 파서 함수를 호출하여 재사용할 수 있습니다:

```lua
-- Identifier 파싱
local new_offset, display_value = dissect_identifier(tvbuf, tree, offset, "Field Name")

-- Consumer 파싱
local new_offset, consumer_info = dissect_consumer(tvbuf, tree, offset, "Consumer")
```

### 기본 타입 헬퍼 함수

코드 재사용성을 위해 기본 타입 헬퍼 함수들을 제공합니다:

#### 값 읽기 함수 (트리에 추가하지 않음)
```lua
local value = read_u8(tvbuf, offset)
local value = read_u32_le(tvbuf, offset)
local value = read_u64_le(tvbuf, offset)
```

#### Dissect 함수 (트리에 추가하면서 파싱)
```lua
-- 기본 타입 dissect (offset 검증 포함)
offset = dissect_u8(tvbuf, tree, offset, field, pktlen)
offset = dissect_u32_le(tvbuf, tree, offset, field, pktlen)
offset = dissect_u64_le(tvbuf, tree, offset, field, pktlen)

-- Length-prefixed 문자열 dissect
offset, str_value = dissect_string_with_u8_len(tvbuf, tree, offset,
                                               len_field, str_field, pktlen)
offset, str_value = dissect_string_with_u32_len(tvbuf, tree, offset,
                                                len_field, str_field, pktlen)
```

이 함수들은 bounds checking을 자동으로 수행하며, 실패 시 nil을 반환합니다.

## 제한사항

- 현재 TCP 세그먼트 재조립은 지원하지 않음
- 초기 구현이므로 제한된 명령어만 지원
- Response 메시지 파싱은 기본적인 수준

## 디렉토리 구조

```
protocol-dissector/
├── Cargo.toml              # Rust 프로젝트 설정
├── README.md               # 이 파일
├── iggy_dissector.lua      # Wireshark Lua dissector
└── src/
    └── lib.rs              # 테스트 코드
```

## 라이선스

Apache License 2.0
