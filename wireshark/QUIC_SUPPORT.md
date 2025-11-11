# Wireshark Dissector - QUIC 지원 현황

## 현재 상태

- ✅ **TCP 지원**: 포트 8090에서 완전히 작동
- ❌ **QUIC 지원**: 현재 미지원

---

## QUIC 검사가 어려운 이유

### 1. 암호화 문제

QUIC는 TLS 1.3을 내장하여 모든 애플리케이션 데이터를 암호화합니다.

```
[TCP의 경우]
네트워크 → TCP 패킷 → Iggy 프로토콜 (평문) → Wireshark가 바로 파싱 ✅

[QUIC의 경우]
네트워크 → UDP 패킷 → QUIC (암호화) → 복호화 필요 ❌
```

Wireshark가 QUIC 패킷을 복호화하려면 **TLS 세션 키**가 필요합니다.

---

### 2. 세션 키 로깅 미지원

**문제**: Iggy 서버/클라이언트가 TLS 세션 키를 파일에 기록하지 않습니다.

**현재 코드** (`core/server/src/quic/quic_server.rs:58-88`):
```rust
let mut server_config = quinn::ServerConfig::with_single_cert(certificate, key)?;
// ❌ KeyLog 설정이 없음!
```

**필요한 코드**:
```rust
use rustls::KeyLogFile;
use std::sync::Arc;

let mut crypto = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certificate, key)?;

// SSLKEYLOGFILE 환경 변수가 있으면 키 로깅 활성화
if let Ok(_) = std::env::var("SSLKEYLOGFILE") {
    crypto.key_log = Arc::new(KeyLogFile::new());
}

let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
```

---

### 3. Dissector의 포트 체크 한계

**현재 코드** (`wireshark/dissector.lua:402-403`):
```lua
local tcp_port = iggy.prefs.tcp_port  -- 8090
local is_request = (pinfo.dst_port == tcp_port)
local is_response = (pinfo.src_port == tcp_port)
```

**문제**:
- QUIC는 UDP 8080 포트 사용
- 포트 체크가 실패하면 `is_request`와 `is_response`가 모두 `false`
- 결과: 파싱 안 됨

**Decode As를 사용해도 작동하지 않는 이유**:
- 사용자가 "Decode As → Iggy"를 선택해도
- 포트가 8090이 아니면 dissector가 데이터를 무시함

---

### 4. Dissector 등록 제한

**현재 코드** (`wireshark/dissector.lua:579-580`):
```lua
DissectorTable.get("tcp.port"):add(iggy.prefs.tcp_port, iggy)
```

**문제**:
- TCP 포트에만 등록됨
- QUIC 복호화 데이터는 별도 dissector table 사용 가능
- 자동 감지 불가능

---

## 해결 방법 비교

### 방법 1: TCP만 지원 (현재)

**구현**:
```lua
-- 현재 코드 그대로 유지
DissectorTable.get("tcp.port"):add(iggy.prefs.tcp_port, iggy)
```

**장점**:
- ✅ 간단하고 안정적
- ✅ TCP는 평문이라 복호화 불필요
- ✅ 코드 수정 없음
- ✅ 100% 정확도

**단점**:
- ❌ QUIC 지원 안 함

**사용 시나리오**:
- TCP만 사용하는 환경
- 프로덕션 환경 (보안 중요)

---

### 방법 2: QUIC 부분 지원 (Decode As)

#### 단계 1: Iggy 서버/클라이언트에 KeyLog 추가

**수정 파일**:
- `core/server/src/quic/quic_server.rs`
- `core/sdk/src/quic/quic_client.rs`

**예시 코드**:
```rust
fn configure_quic(config: QuicConfig) -> Result<quinn::ServerConfig, QuicError> {
    let (certificate, key) = /* ... */;

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate, key)?;

    // SSLKEYLOGFILE 지원
    if let Ok(_) = std::env::var("SSLKEYLOGFILE") {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // ... transport config ...
    Ok(server_config)
}
```

#### 단계 2: Dissector에서 포트 체크 개선

**옵션 A - 프로토콜 구조 기반 판단** (권장):
```lua
function detect_message_type(buffer, buflen)
    if buflen < 8 then
        return false, false
    end

    local first_field = buffer(0, 4):le_uint()

    -- Request: LENGTH(4) + CODE(4) + PAYLOAD
    --   LENGTH는 보통 큰 값 (페이로드 크기)
    -- Response: STATUS(4) + LENGTH(4) + PAYLOAD
    --   STATUS는 보통 0-1000 범위

    if first_field <= 1000 then
        return false, true  -- Response
    else
        return true, false  -- Request
    end
end

function iggy.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol:set("IGGY")
    local buflen = buffer:len()
    local is_request, is_response = detect_message_type(buffer, buflen)
    -- ...
end
```

**옵션 B - 다중 포트 체크**:
```lua
iggy.prefs.quic_port = Pref.uint("QUIC Port", 8080, "Target QUIC server port")

function iggy.dissector(buffer, pinfo, tree)
    local tcp_port = iggy.prefs.tcp_port
    local quic_port = iggy.prefs.quic_port
    local is_request = (pinfo.dst_port == tcp_port or pinfo.dst_port == quic_port)
    local is_response = (pinfo.src_port == tcp_port or pinfo.src_port == quic_port)
    -- ...
end
```

#### 사용 방법

1. **SSLKEYLOGFILE 설정**:
```bash
export SSLKEYLOGFILE=~/sslkeylog.txt
./iggy-server
```

2. **Wireshark 설정**:
   - Edit → Preferences → Protocols → TLS
   - "(Pre)-Master-Secret log filename" 필드에 `~/sslkeylog.txt` 입력

3. **패킷 캡처**:
```bash
tshark -o tls.keylog_file:~/sslkeylog.txt \
       -i lo0 \
       -f "udp port 8080"
```

4. **Decode As 설정** (필요시):
   - QUIC 패킷 우클릭 → Decode As...
   - Current에서 "Iggy" 선택

**장점**:
- ✅ QUIC 복호화 가능
- ✅ 개발/디버깅에 유용
- ✅ 구현이 비교적 간단 (10-20줄 코드)

**단점**:
- ❌ Iggy 코드 수정 필요
- ❌ SSLKEYLOGFILE 환경 변수 설정 필요
- ❌ Decode As 수동 지정 필요 (자동 감지 안 됨)
- ❌ 프로토콜 구조 기반 판단은 edge case에서 부정확할 수 있음
- ⚠️ 보안 위험: 세션 키가 파일에 저장됨 (개발 환경 전용)

**사용 시나리오**:
- 개발 환경에서 QUIC 트래픽 분석
- 프로토콜 디버깅
- 성능 테스트

---

### 방법 3: 완전한 QUIC 지원 (ALPN)

#### 구현 요구사항

1. **Iggy에 ALPN 추가**:
```rust
// 서버
let mut server_config = quinn::ServerConfig::with_single_cert(certificate, key)?;
server_config.supported_protocols(vec![b"iggy".to_vec()]);

// 클라이언트
let mut client_config = ClientConfig::new(Arc::new(crypto));
client_config.alpn_protocols = vec![b"iggy".to_vec()];
```

2. **Wireshark dissector 등록**:
```lua
-- QUIC의 ALPN "iggy"에 자동 연결
-- (Wireshark 내부 QUIC dissector 구조 이해 필요)
```

**장점**:
- ✅ 자동 감지 가능
- ✅ Decode As 불필요
- ✅ 프로덕션 환경에 적합

**단점**:
- ❌ 구현 복잡도 높음
- ❌ Iggy 서버/클라이언트 수정 필요
- ❌ Wireshark QUIC dissector 내부 구조 이해 필요

**사용 시나리오**:
- 프로덕션 환경에서 QUIC을 주로 사용
- 완전한 자동화 필요

---

## 비교 요약

| 항목 | 방법 1: TCP만 | 방법 2: Decode As | 방법 3: 완전 지원 |
|------|--------------|------------------|------------------|
| **구현 난이도** | 매우 쉬움 | 중간 | 어려움 |
| **Iggy 코드 수정** | 불필요 | KeyLog만 추가 | KeyLog + ALPN |
| **사용 편의성** | 자동 | 수동 (Decode As) | 자동 |
| **QUIC 지원** | 없음 | 부분 (복호화 가능) | 완전 |
| **정확도** | 100% | 90-95% | 100% |
| **보안** | 안전 | 위험 (키 노출) | 안전 |
| **유지보수** | 쉬움 | 보통 | 어려움 |

---

## 권장사항

### 개발 환경
→ **방법 2 (Decode As)** 추천
- KeyLog 추가는 간단 (4-5줄 코드)
- QUIC 트래픽 디버깅 가능
- 유연성 높음

### 프로덕션 환경
→ **방법 1 (TCP만)** 유지
- SSLKEYLOGFILE은 보안 위험
- TCP만으로 충분한 경우가 많음
- 안정적이고 간단

### 장기 로드맵
→ **방법 3 (ALPN)** 고려
- QUIC을 주 프로토콜로 사용하는 경우
- 완전한 자동화 필요시

---

## 참고자료

### TLS 키 로깅
- [Wireshark TLS Decryption](https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
- [rustls KeyLog](https://docs.rs/rustls/latest/rustls/trait.KeyLog.html)
- [quinn SSLKEYLOGFILE](https://docs.rs/quinn/latest/quinn/)

### QUIC 프로토콜
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
- [Wireshark QUIC](https://wiki.wireshark.org/QUIC)

### Wireshark Dissector
- [Lua Dissector API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html)
- [Decode As](https://wiki.wireshark.org/Decode_As)
