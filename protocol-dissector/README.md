# Iggy Protocol Dissector

Wireshark Lua 기반 Dissector로 iggy 프로토콜의 바이너리 통신(TCP/QUIC) 데이터를 분석합니다.

## 개요

이 프로젝트는 iggy 프로토콜의 바이너리 메시지를 Wireshark에서 사람이 읽기 쉽게 파싱하는 Lua dissector를 제공합니다. 초기 구현으로 다음 명령어를 지원합니다:

- **Ping** (code: 1) - payload 없음
- **GetStats** (code: 10) - payload 없음
- **LoginUser** (code: 38) - username, password, version, context를 포함하는 payload

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

   # Linux
   cp iggy_dissector.lua ~/.local/lib/wireshark/plugins/

   # Windows
   copy iggy_dissector.lua %APPDATA%\Wireshark\plugins\
   ```

2. 또는 Wireshark에서 직접 로드:
   - Wireshark 실행
   - Analyze > Reload Lua Plugins
   - 또는 `-X lua_script:iggy_dissector.lua` 옵션으로 시작

3. TCP 포트 8090 또는 8091의 트래픽을 캡처하면 자동으로 Iggy 프로토콜이 파싱됩니다.

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
```

**참고**: 테스트는 시스템에 `tshark`가 설치되어 있어야 하며, 로컬 네트워크 인터페이스(lo0)에 대한 캡처 권한이 필요합니다.

## 지원하는 명령어

현재 구현된 명령어:

| Code | 명령어 | Payload |
|------|--------|---------|
| 1 | Ping | 없음 |
| 10 | GetStats | 없음 |
| 38 | LoginUser | username, password, version, context |

## 확장성

Lua 스크립트는 모듈화되어 있어 새로운 명령어를 쉽게 추가할 수 있습니다:

1. `command_names` 테이블에 새 명령어 코드와 이름 추가
2. 필요시 새 필드 정의 (ProtoField)
3. `command_handlers` 테이블에 payload 파서 추가

```lua
command_handlers[NEW_CODE] = {
    name = "NewCommand",
    parse_payload = function(buffer, pinfo, tree, offset)
        -- payload 파싱 로직
    end
}
```

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
