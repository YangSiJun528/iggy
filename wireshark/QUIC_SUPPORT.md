# Wireshark Dissector - QUIC 지원 가이드

## 현재 상태

- ✅ **TCP 지원**: 포트 8090에서 완전히 작동
- ❌ **QUIC 지원**: 현재 미지원 (복호화 불가)

---

## 핵심 개념: 인증서 vs SSLKEYLOGFILE

### Iggy 설정 파일 (`core/configs/server.toml`)

```toml
[quic.certificate]
self_signed = true
cert_file = "core/certs/iggy_cert.pem"  # ← TLS 인증서 (암호화용)
key_file = "core/certs/iggy_key.pem"    # ← 개인 키 (암호화용)
```

### 차이점

| 항목 | TLS 인증서 (cert/key) | SSLKEYLOGFILE |
|------|---------------------|---------------|
| **목적** | QUIC 암호화 통신 | Wireshark 복호화 분석 |
| **역할** | 서버 인증 + 데이터 암호화 | TLS 세션 키 기록 |
| **위치** | 설정 파일 (이미 있음) | 환경 변수 (현재 없음) |
| **사용** | 프로덕션 필수 | 디버깅 전용 |
| **보안** | 안전 | 위험 (키 노출) |

### 비유

```
cert_file + key_file = 금고 자물쇠와 열쇠
  → QUIC 통신을 암호화/복호화 (정상 작동)

SSLKEYLOGFILE = CCTV 녹화
  → 나중에 "무슨 일이 있었는지" 보기 위해 기록
  → 통신 자체와는 무관
```

---

## QUIC 검사가 어려운 이유

### 1. 암호화 문제

```
[TCP]
네트워크 → TCP 패킷 → Iggy 프로토콜 (평문) → Wireshark 파싱 ✅

[QUIC]
네트워크 → UDP 패킷 → QUIC (암호화) → 복호화 필요 ❌
                                        ↓
                              세션 키가 없으면 복호화 불가
```

**현재 상황**:
- Iggy는 `cert_file`/`key_file`로 암호화 통신 가능 ✅
- 하지만 세션 키를 파일에 기록하지 않음 ❌
- Wireshark는 세션 키 없이 복호화 불가 ❌

---

### 2. 세션 키 로깅 미지원

**현재 코드** (`core/server/src/quic/quic_server.rs:59`):
```rust
let mut server_config = quinn::ServerConfig::with_single_cert(certificate, key)?;
// ❌ KeyLog 설정 없음
```

**필요한 수정**:
```rust
// rustls ServerConfig 직접 생성
let mut crypto = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certificate, key)?;

// SSLKEYLOGFILE 환경 변수 체크
if let Ok(_) = std::env::var("SSLKEYLOGFILE") {
    crypto.key_log = Arc::new(rustls::KeyLogFile::new());
}

let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
```

---

### 3. Dissector 포트 체크 한계

**현재 코드** (`wireshark/dissector.lua:402-403`):
```lua
local server_port = iggy.prefs.server_port  -- 8090 (TCP)
local is_request = (pinfo.dst_port == server_port)
local is_response = (pinfo.src_port == server_port)
```

**문제**:
- QUIC는 UDP 8080 포트 사용
- 포트가 8090이 아니면 `is_request`/`is_response` 모두 `false`
- Decode As 사용해도 포트 체크 때문에 작동 안 함

---

## 해결 방법 비교

### 방법 1: TCP만 지원 (현재)

**장점**:
- ✅ 수정 불필요
- ✅ 평문 파싱
- ✅ 100% 정확
- ✅ 안전

**단점**:
- ❌ QUIC 미지원

**적용 대상**: 프로덕션 환경

---

### 방법 2: QUIC 지원 (Decode As)

#### Step 1: Iggy 코드 수정

**파일**: `core/server/src/quic/quic_server.rs`

```rust
fn configure_quic(config: QuicConfig) -> Result<quinn::ServerConfig, QuicError> {
    let (certificate, key) = /* ... 기존 코드 ... */;

    // rustls config 생성
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate, key)?;

    // SSLKEYLOGFILE 지원 추가
    if let Ok(_) = std::env::var("SSLKEYLOGFILE") {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        info!("QUIC key logging enabled");
    }

    let mut server_config = quinn::ServerConfig::with_crypto(
        Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?)
    );

    // ... 기존 transport config ...
}
```

**클라이언트도 동일하게** (`core/sdk/src/quic/quic_client.rs`)

#### Step 2: Dissector 수정 (선택사항)

**옵션 A - 프로토콜 구조 기반** (권장):
```lua
function detect_message_type(buffer, buflen)
    if buflen < 8 then return false, false end

    local first = buffer(0, 4):le_uint()
    -- Response STATUS는 0-1000, Request LENGTH는 더 큼
    if first <= 1000 then
        return false, true  -- Response
    else
        return true, false  -- Request
    end
end
```

**옵션 B - 다중 포트**:
```lua
local server_port = iggy.prefs.server_port
local quic_port = 8080
local is_request = (pinfo.dst_port == server_port or pinfo.dst_port == quic_port)
```

#### Step 3: 사용 방법

```bash
# 1. 환경변수 설정
export SSLKEYLOGFILE=~/iggy-sslkey.txt

# 2. Iggy 서버 실행
./iggy-server

# 3. Wireshark 설정
# Edit → Preferences → Protocols → TLS
# "(Pre)-Master-Secret log filename": ~/iggy-sslkey.txt

# 4. 패킷 캡처
tshark -o tls.keylog_file:~/iggy-sslkey.txt -i lo0 -f "udp port 8080"

# 5. Decode As (필요시)
# QUIC 패킷 우클릭 → Decode As → Iggy
```

**장점**:
- ✅ QUIC 복호화 가능
- ✅ 간단한 구현 (10줄)
- ✅ 디버깅 유용

**단점**:
- ❌ 코드 수정 필요
- ❌ 환경변수 설정 필요
- ❌ Decode As 수동
- ⚠️ 보안 위험 (개발 전용)

**적용 대상**: 개발 환경

---

### 방법 3: 완전 자동화 (ALPN)

Iggy에 ALPN 추가:
```rust
server_config.supported_protocols(vec![b"iggy".to_vec()]);
```

**장점**: 자동 감지
**단점**: 구현 복잡, Wireshark 내부 이해 필요
**적용 대상**: 장기 로드맵

---

## 비교표

| 항목 | TCP만 | Decode As | ALPN |
|------|------|-----------|------|
| 난이도 | 쉬움 | 중간 | 어려움 |
| 코드 수정 | 불필요 | KeyLog만 | KeyLog+ALPN |
| 자동화 | 자동 | 수동 | 자동 |
| QUIC 지원 | 없음 | 부분 | 완전 |
| 보안 | 안전 | 위험 | 안전 |

---

## 실전 가이드

### QUIC 트래픽 분석 (개발 환경)

```bash
# 1. Iggy 재빌드 (KeyLog 추가 후)
cargo build --release

# 2. 환경변수 설정
export SSLKEYLOGFILE=~/iggy-sslkey.txt

# 3. 서버 시작
./target/release/iggy-server

# 4. 별도 터미널에서 패킷 캡처
tshark \
  -o tls.keylog_file:~/iggy-sslkey.txt \
  -i lo0 \
  -f "udp port 8080" \
  -Y "quic" \
  -V

# 5. 클라이언트 실행 (별도 터미널)
export SSLKEYLOGFILE=~/iggy-sslkey.txt
./target/release/iggy
```

### 세션 키 확인

```bash
# TLS handshake 후 파일 확인
cat ~/iggy-sslkey.txt

# 다음과 같은 형식:
# CLIENT_RANDOM 5a7d... 6b8c9d...
# SERVER_HANDSHAKE_TRAFFIC_SECRET 7b8c... ae4f5g...
```

### Wireshark에서 복호화 확인

1. QUIC 패킷 선택
2. 패킷 상세 → "Decrypted QUIC Payload" 확인
3. Decode As → Iggy 선택
4. Iggy 프로토콜 필드 확인

---

## 자주 묻는 질문 (FAQ)

### Q1: cert_file이 있는데 왜 SSLKEYLOGFILE이 필요한가요?

**A**: 다른 목적입니다.
- `cert_file`: 암호화 통신용 (정상 작동)
- `SSLKEYLOGFILE`: Wireshark 분석용 (디버깅)

### Q2: 유튜브 QUIC는 왜 분석 안 되나요?

**A**: 브라우저도 기본적으로 키를 로깅하지 않습니다.

```bash
# Chrome에 SSLKEYLOGFILE 설정 후 실행
export SSLKEYLOGFILE=~/sslkey.txt
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
```

### Q3: 프로덕션에서 사용해도 되나요?

**A**: 절대 안 됩니다! SSLKEYLOGFILE은:
- TLS 세션 키를 평문으로 저장
- 누구나 트래픽 복호화 가능
- 심각한 보안 위험

**개발/디버깅 전용**입니다.

### Q4: Decode As 없이 자동으로 안 되나요?

**A**: 현재는 안 됩니다. ALPN을 추가하면 가능하지만:
- Iggy 코드 수정 필요
- Wireshark QUIC dissector 구조 이해 필요
- 복잡도 높음

---

## 권장사항

| 환경 | 권장 방법 | 이유 |
|------|----------|------|
| **개발** | 방법 2 (Decode As) | 간단, 유연, 디버깅 가능 |
| **프로덕션** | 방법 1 (TCP만) | 안전, 안정적 |
| **장기** | 방법 3 (ALPN) | 완전 자동화 |

---

## 참고 자료

- [Wireshark TLS Decryption](https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
- [rustls KeyLog](https://docs.rs/rustls/latest/rustls/struct.KeyLogFile.html)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
- [Wireshark Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html)
