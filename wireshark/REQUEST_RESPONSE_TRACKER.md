# Request-Response Tracker Module 동작 방식 문서

## 개요

`ReqRespTracker`는 Wireshark의 Conversation API를 활용하여 파이프라이닝된 프로토콜에서 요청과 응답을 매칭하는 모듈입니다. TCP 연결에서 여러 요청/응답이 순서대로 전송되는 경우에도 정확하게 쌍을 찾아냅니다.

## 목차

- [핵심 개념](#핵심-개념)
- [데이터 구조](#데이터-구조)
- [동작 흐름](#동작-흐름)
- [매칭 알고리즘](#매칭-알고리즘)
- [Wireshark Multi-pass 처리](#wireshark-multi-pass-처리)
- [메모리 관리](#메모리-관리)
- [사용 예시](#사용-예시)
- [제약 사항](#제약-사항)

---

## 핵심 개념

### 1. Conversation API란?

Wireshark의 Conversation은 **두 엔드포인트 간의 모든 트래픽**을 추적하는 객체입니다:

- **TCP 연결의 경우**: `(IP1:Port1 ↔ IP2:Port2)` 조합으로 식별
- **자동 관리**: Wireshark가 생성 및 생명주기 관리
- **데이터 저장**: Protocol-specific 데이터를 저장 가능
  ```lua
  conversation[proto] = data
  ```

### 2. 파이프라이닝 프로토콜

여러 요청을 응답을 기다리지 않고 연속으로 전송하는 방식:

```
Time →
Client: REQ1 ----→ REQ2 ----→ REQ3 ----→
Server:      ←---- RESP1 ←---- RESP2 ←---- RESP3
```

**특징:**
- 응답은 요청 순서대로 도착 (FIFO)
- 네트워크 효율성 향상 (왕복 지연 감소)
- 매칭 복잡도 증가

---

## 데이터 구조

### Conversation Data 스키마

```lua
conv_data = {
    requests = {
        [frame_number] = request_data,  -- 요청 프레임 번호 → 명령 코드
        -- 예: [42] = 38 (LoginUser command)
        ...
    },
    matched = {
        [resp_frame_num] = req_frame_num,  -- 응답 프레임 → 매칭된 요청 프레임
        -- 예: [45] = 42 (Frame 45의 응답은 Frame 42의 요청과 매칭)
        ...
    }
}
```

### 핵심 아이디어

| 테이블 | 목적 | 키 | 값 |
|--------|------|-----|-----|
| `requests` | 모든 요청 저장 | 요청 프레임 번호 | 요청 데이터 (명령 코드 등) |
| `matched` | 매칭 결과 캐싱 | 응답 프레임 번호 | 매칭된 요청 프레임 번호 |

**왜 두 개의 테이블?**
- `requests`: 요청 정보의 영구 저장소
- `matched`: 응답 → 요청 매핑의 캐시 (성능 최적화)

---

## 동작 흐름

### 요청 패킷 처리 (record_request)

```
┌─────────────────────────────────────────┐
│ 1. pinfo.conversation 획득              │
│    (Wireshark가 자동 제공)              │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 2. conv[iggy] 에서 기존 데이터 로드      │
│    없으면 새로 초기화                    │
│    { requests = {}, matched = {} }      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 3. 요청 정보 저장                        │
│    conv_data.requests[frame_num] = code │
│                                          │
│    예: requests[42] = 38 (LoginUser)    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 4. 업데이트된 데이터 다시 저장           │
│    conv[iggy] = conv_data               │
└─────────────────────────────────────────┘
```

#### 코드 예시

```lua
function ReqRespTracker:record_request(pinfo, request_data)
    local conv = pinfo.conversation
    local conv_data = conv[self.proto] or { requests = {}, matched = {} }

    -- Store request indexed by frame number
    conv_data.requests[pinfo.number] = request_data
    conv[self.proto] = conv_data

    return true
end
```

#### 실행 예시

```lua
-- Frame #42: LoginUser 요청 패킷
pinfo.number = 42
request_data = 38  -- LoginUser command code

-- 저장 후 상태:
conv_data.requests = {
    [42] = 38,
}
```

### 응답 패킷 처리 (find_request)

```
┌─────────────────────────────────────────┐
│ 1. pinfo.conversation 획득              │
│    conv_data = conv[iggy]               │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ 2. 캐시 확인                             │
│    matched[resp_frame_num] 있나?        │
└──────┬────────────────────┬─────────────┘
       │ YES                │ NO
       │                    │
       ▼                    ▼
┌──────────────┐   ┌────────────────────────┐
│ 캐시된 값    │   │ 3. 역방향 검색          │
│ 즉시 반환    │   │    - 현재 프레임보다 앞 │
└──────────────┘   │    - 아직 매칭 안됨     │
                   │    - 가장 최근 것       │
                   └──────────┬──────────────┘
                              │
                              ▼
                   ┌────────────────────────┐
                   │ 4. 매칭 결과 캐싱       │
                   │    matched[resp] = req │
                   │    conv[iggy] 업데이트 │
                   └──────────┬──────────────┘
                              │
                              ▼
                   ┌────────────────────────┐
                   │ 5. 요청 데이터 반환     │
                   │    requests[req_frame] │
                   └────────────────────────┘
```

#### 실행 예시

**시나리오 1: 캐시 히트**

```lua
-- Frame #45: 응답 패킷 도착
pinfo.number = 45

-- 이미 매칭 정보가 있는 경우
matched[45] = 42  -- 이전 패스에서 계산됨

-- 즉시 반환
return requests[42]  -- = 38 (LoginUser)
```

**시나리오 2: 캐시 미스 - 검색 필요**

```lua
-- Frame #45: 응답 패킷 도착 (첫 dissection)
pinfo.number = 45

-- 현재 상태:
requests = {
    [40] = 1,   -- Ping
    [42] = 38,  -- LoginUser
    [44] = 302, -- CreateTopic
    [50] = 1,   -- Ping (미래 프레임)
}

matched = {
    [41] = 40,  -- Frame 41 응답은 Frame 40 요청과 매칭됨
}

-- 검색 과정:
-- 1. Frame 50 무시 (50 > 45, 미래 요청)
-- 2. Frame 44 검토 → 아직 매칭 안됨 ✓
-- 3. Frame 42 검토 → 아직 매칭 안됨 ✓
-- 4. Frame 40 무시 (이미 matched[41]과 매칭됨)

-- 44와 42 중 더 최근인 것 선택 → 44
matched[45] = 44
return requests[44]  -- = 302 (CreateTopic)
```

---

## 매칭 알고리즘

### 알고리즘 상세

```lua
function ReqRespTracker:find_request(pinfo)
    local conv = pinfo.conversation
    local conv_data = conv[self.proto]
    local resp_frame_num = pinfo.number

    -- Step 1: 캐시 확인
    if conv_data.matched[resp_frame_num] then
        return conv_data.requests[conv_data.matched[resp_frame_num]]
    end

    -- Step 2: 역방향 검색
    local best_req_frame = nil
    local best_req_data = nil

    for req_frame, req_data in pairs(conv_data.requests) do
        if req_frame < resp_frame_num then
            -- 이미 매칭된 요청인지 확인
            local already_matched = false
            for _, matched_req_frame in pairs(conv_data.matched) do
                if matched_req_frame == req_frame then
                    already_matched = true
                    break
                end
            end

            -- 매칭 안됐고 더 최근이면 업데이트
            if not already_matched then
                if not best_req_frame or req_frame > best_req_frame then
                    best_req_frame = req_frame
                    best_req_data = req_data
                end
            end
        end
    end

    -- Step 3: 결과 캐싱
    if best_req_frame then
        conv_data.matched[resp_frame_num] = best_req_frame
        conv[self.proto] = conv_data
    end

    return best_req_data
end
```

### 의사 코드 (Python 스타일)

```python
def find_request(resp_frame_num):
    # 1. 캐시 확인
    if resp_frame_num in matched:
        return requests[matched[resp_frame_num]]

    # 2. 후보 필터링
    candidates = []
    for req_frame, req_data in requests.items():
        # 미래 요청 제외
        if req_frame >= resp_frame_num:
            continue

        # 이미 매칭된 요청 제외
        if req_frame in matched.values():
            continue

        candidates.append((req_frame, req_data))

    # 3. 가장 최근 요청 선택
    if not candidates:
        return None

    best = max(candidates, key=lambda x: x[0])

    # 4. 캐싱
    matched[resp_frame_num] = best[0]
    return best[1]
```

### 왜 "가장 최근의 매칭 안된 요청"인가?

파이프라이닝 프로토콜의 FIFO 특성:

```
Frame#  Direction  Command
────────────────────────────────
  40    →          Ping          (REQ1)
  41    ←          Ping OK       (RESP1) → matches 40
  42    →          LoginUser     (REQ2)
  44    →          CreateTopic   (REQ3)
  45    ←          LoginUser OK  (RESP2) → matches ?

응답 순서 = 요청 순서
RESP2는 REQ2와 매칭되어야 함
→ 매칭 안된 요청 중 가장 최근 = Frame 42
```

### 시간 복잡도

- **캐시 히트**: O(1)
- **캐시 미스**: O(n × m)
  - n = requests 테이블 크기
  - m = matched 테이블 크기
- **평균**: O(1) - 대부분 캐시 히트

---

## Wireshark Multi-pass 처리

### Wireshark가 패킷을 여러 번 dissect하는 이유

Wireshark는 다음 상황에서 패킷을 재분석합니다:
1. **초기 로드**: 파일을 처음 열 때
2. **사용자 클릭**: 패킷 리스트에서 패킷 선택 시
3. **필터 적용**: Display filter 변경 시
4. **재로드**: 캡처 파일 다시 열기

### Pass별 동작 예시

#### Pass 1: 초기 로드 (순차 처리)

```lua
-- Frame 40 dissect
record_request(pinfo, 1)  -- Ping
-- conv_data.requests[40] = 1

-- Frame 41 dissect
find_request(pinfo)
-- matched[41] = 40 계산 및 캐싱
-- return 1

-- Frame 42 dissect
record_request(pinfo, 38)  -- LoginUser
-- conv_data.requests[42] = 38

-- Frame 44 dissect
record_request(pinfo, 302)  -- CreateTopic
-- conv_data.requests[44] = 302

-- Frame 45 dissect
find_request(pinfo)
-- matched[45] = 42 계산 및 캐싱
-- return 38
```

#### Pass 2: 사용자가 Frame 45만 클릭

```lua
-- Frame 45 re-dissect (다른 프레임은 dissect 안됨!)
find_request(pinfo)

-- 문제: requests 테이블이 비어있을 수 있음
-- 해결: matched[45] 캐시 확인
--       → 42 발견
--       → return requests[42] = 38 (즉시 반환)
```

#### Pass 3: 필터 적용 (iggy.response)

```lua
-- Frame 41, 45만 dissect (요청 프레임은 건너뜀)

-- Frame 41 dissect
find_request(pinfo)
-- matched[41] = 40 (캐시 히트)
-- return requests[40] = 1

-- Frame 45 dissect
find_request(pinfo)
-- matched[45] = 42 (캐시 히트)
-- return requests[42] = 38
```

### 캐싱의 중요성

**캐시 없이:**
```lua
-- Pass 2에서 Frame 45만 dissect
-- requests 테이블이 비어있음 (Frame 42가 dissect 안됨)
-- find_request() 실패 → 매칭 불가 ❌
```

**캐시 있음:**
```lua
-- Pass 2에서 Frame 45만 dissect
-- matched[45] = 42 캐시 확인
-- requests[42] 접근 (Pass 1에서 저장됨)
-- 매칭 성공 ✓
```

### Conversation 데이터의 지속성

```lua
-- Pass 1: 데이터 저장
conv[iggy] = { requests = {40: 1, 42: 38}, matched = {41: 40, 45: 42} }

-- Pass 2: 데이터 유지 (Wireshark가 관리)
conv[iggy]  -- 여전히 동일한 데이터 접근 가능
```

**핵심:** Conversation 객체는 Wireshark가 세션 동안 유지하므로, 어느 패스에서든 동일한 데이터에 접근 가능

---

## 메모리 관리

### Wireshark의 자동 관리

```lua
function ReqRespTracker:reset()
    -- No-op: Conversation data is managed by Wireshark
end
```

#### 왜 수동 정리가 필요 없는가?

| 항목 | 수동 관리 (레거시) | Conversation API |
|------|-------------------|------------------|
| **저장소** | 전역 Lua 테이블 | Wireshark Conversation 객체 |
| **생명주기** | Lua 스크립트와 동일 | TCP 연결과 동일 |
| **정리 시점** | `init()` 호출 시 | TCP 연결 종료 시 자동 |
| **메모리 누수 위험** | 높음 (수동 정리 필요) | 낮음 (자동 관리) |

#### 메모리 관리 흐름

```
┌──────────────────────────┐
│ TCP 연결 시작             │
│ (SYN, SYN-ACK, ACK)      │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Wireshark가 Conversation │
│ 객체 자동 생성            │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Dissector가 데이터 저장   │
│ conv[iggy] = {...}       │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ 패킷 dissection 계속...  │
│ (데이터 읽기/쓰기)        │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ TCP 연결 종료             │
│ (FIN, FIN-ACK)           │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ Wireshark가 Conversation │
│ 객체 자동 삭제            │
│ (메모리 해제)             │
└──────────────────────────┘
```

### 새 캡처 파일 로드 시

```lua
function iggy.init()
    request_tracker:reset()  -- No-op
    -- Wireshark가 이전 Conversation 객체들을 모두 정리함
    -- 새 파일의 Conversation들은 자동으로 생성됨
end
```

---

## 사용 예시

### 1. 초기화

```lua
-- dissector.lua 상단에서
local request_tracker = ReqRespTracker.new(iggy)
```

### 2. Dissector에서의 통합

```lua
function iggy.dissector(buffer, pinfo, tree)
    local server_port = iggy.prefs.server_port
    local is_request = (pinfo.dst_port == server_port)
    local is_response = (pinfo.src_port == server_port)

    if is_request then
        -- 요청 패킷 처리
        local command_code = buffer(4, 4):le_uint()
        local command_info = COMMANDS[command_code]

        if command_info then
            -- 요청 정보 저장
            request_tracker:record_request(pinfo, command_code)

            -- 프로토콜 트리에 정보 추가
            subtree:add(cf.req_command_name, command_info.name):set_generated()

            -- Payload dissection
            command_info.request_payload_dissector(...)
        end

    elseif is_response then
        -- 응답 패킷 처리
        local status_code = buffer(0, 4):le_uint()

        -- 매칭되는 요청 찾기
        local command_code = request_tracker:find_request(pinfo)
        local command_info = command_code and COMMANDS[command_code]

        if command_info then
            -- 매칭된 요청의 정보 사용
            subtree:add(cf.req_command_name, command_info.name):set_generated()

            -- 응답 payload dissection (요청 타입에 맞게)
            if status_code == 0 then
                command_info.response_payload_dissector(...)
            end
        else
            -- 매칭 실패 (알 수 없는 응답)
            subtree:add(cf.req_command_name, "Unknown"):set_generated()
        end
    end
end
```

### 3. 실제 패킷 처리 예시

```lua
-- Packet #42: LoginUser 요청
buffer = [38 00 00 00] [username_len] [username] ...
pinfo.number = 42
pinfo.dst_port = 8090

-- is_request = true
command_code = 38  -- LoginUser
request_tracker:record_request(pinfo, 38)

-- Info column 업데이트
pinfo.cols.info:set("Request: LoginUser (code=38, length=42)")
```

```lua
-- Packet #45: LoginUser 응답
buffer = [00 00 00 00] [04 00 00 00] [user_id]
pinfo.number = 45
pinfo.src_port = 8090

-- is_response = true
status_code = 0  -- OK

-- 매칭되는 요청 찾기
command_code = request_tracker:find_request(pinfo)  -- → 38
command_info = COMMANDS[38]  -- → LoginUser

-- 응답 dissection
command_info.response_payload_dissector(...)
-- → user_id 필드 파싱

-- Info column 업데이트
pinfo.cols.info:set("Response: LoginUser OK (length=4)")
```

---

## 제약 사항

### 1. Wireshark 버전 요구사항

**필수:** Wireshark 4.6 이상

- **이유:** Conversation API의 Lua 바인딩은 [MR #18890](https://gitlab.com/wireshark/wireshark/-/merge_requests/18890)에서 추가됨
- **확인 방법:**
  ```bash
  wireshark --version
  # Wireshark 4.6.0 이상이어야 함
  ```

### 2. 프로토콜 제약

**FIFO 순서 보장 필요**

```lua
-- ✓ 지원됨: FIFO 응답
REQ1 → REQ2 → REQ3
     RESP1 ← RESP2 ← RESP3

-- ✗ 지원 안됨: Out-of-order 응답
REQ1 → REQ2 → REQ3
     RESP2 ← RESP1 ← RESP3
```

**Out-of-order 응답이 필요한 경우:**
- Transaction ID 기반 매칭 필요
- 요청/응답에 명시적인 ID 필드 포함
- `record_request()`와 `find_request()`를 수정하여 ID 기반 매칭 구현

### 3. 연결 단위 추적

**Conversation 단위로 독립적**

```lua
-- Connection 1: 192.168.1.100:12345 ↔ server:8090
conv1[iggy] = { requests = {10: 1, 12: 38}, ... }

-- Connection 2: 192.168.1.101:54321 ↔ server:8090
conv2[iggy] = { requests = {15: 302, 20: 1}, ... }

-- 서로 독립적으로 관리됨
```

**장점:** 다중 클라이언트 자동 지원
**제약:** 연결이 끊기면 데이터도 사라짐 (재연결 시 새 Conversation)

### 4. 성능 고려사항

**대량 파이프라이닝 시 주의**

```lua
-- 예: 1000개 요청 → 1000개 응답
requests = { [1]=cmd1, [2]=cmd2, ..., [1000]=cmd1000 }

-- 응답 매칭 시 최악의 경우:
-- O(n × m) = O(1000 × 1000) = O(1,000,000)
```

**최적화 방법:**
1. 첫 패스 후 `matched` 캐시 활용 → O(1)
2. 필요시 정렬된 리스트로 변경 → O(log n)

---

## 장점

### ✅ Multi-pass 안전성

```lua
-- Pass 1: 전체 dissection
-- Pass 2: 특정 패킷만 re-dissection
-- Pass 3: 필터링 후 dissection

-- 모든 경우에 일관된 매칭 결과 보장
```

### ✅ 자동 메모리 관리

```lua
-- 수동 정리 불필요
-- Wireshark가 TCP 연결 종료 시 자동 해제
-- 메모리 누수 위험 없음
```

### ✅ 파이프라이닝 지원

```lua
-- 여러 요청/응답이 동시에 진행 중이어도
-- 정확한 매칭 보장
```

### ✅ 캐싱 최적화

```lua
-- 첫 dissection: O(n) 계산
-- 이후 dissection: O(1) 캐시 조회
```

### ✅ 재사용 가능

```lua
-- 다른 프로토콜에도 적용 가능
local http2_tracker = ReqRespTracker.new(http2_proto)
local grpc_tracker = ReqRespTracker.new(grpc_proto)
```

---

## 참고 자료

### Wireshark 문서

- [Lua API Reference - Pinfo](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html)
- [Conversation API MR #18890](https://gitlab.com/wireshark/wireshark/-/merge_requests/18890)
- [Wireshark Issue #15396](https://gitlab.com/wireshark/wireshark/-/issues/15396)

### 커뮤니티 자료

- [Stack Overflow: Lua dissector request-response matching](https://stackoverflow.com/questions/67834060/wireshark-lua-dissector-response-request)
- [Ask Wireshark: Lua dissector state management](https://osqa-ask.wireshark.org/questions/42711/lua-dissector-puzzle-how-to-save-state/)

---

## 버전 히스토리

| 버전 | 날짜 | 변경 사항 |
|------|------|-----------|
| 1.0 | 2025-11 | 초기 버전 (Conversation API 기반) |
| 0.1 | 2025-11 | 레거시 버전 (프레임 번호 기반 수동 추적) |

---

## 라이선스

이 문서는 Iggy 프로젝트의 일부입니다.
