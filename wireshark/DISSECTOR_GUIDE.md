# Wireshark Lua Dissector 작성 가이드

Wireshark Lua dissector를 작성하면서 겪은 실수와 주의사항을 정리한 문서입니다.

## 1. set_generated()의 의미

### 목적
`set_generated()`는 필드가 패킷 데이터에서 **추론된 값(inferred data)**임을 표시합니다.

```lua
-- command_name은 command code에서 파생된 값
subtree:add(cf.req_command_name, command_name):set_generated()
```

### 동작
- **Wireshark GUI**: 필드가 시각적으로 구분 표시됨 (회색 등)
- **tshark JSON 출력**: 필드는 **정상적으로 출력됨**
- 필드를 숨기거나 제거하는 것이 **아님**

### 사용 예시
```lua
-- message_type은 패킷 방향에서 결정된 값
subtree:add(cf.message_type, "Request"):set_generated()

-- command_name은 command code에서 조회한 값
subtree:add(cf.req_command_name, command_name):set_generated()

-- status_name은 status code에서 조회한 값
subtree:add(cf.resp_status_name, status_name):set_generated()

-- kind 설명 텍스트 추가
local kind_item = tree:add(f.stream_id_kind, buffer(offset, 1))
if stream_id_kind == 1 then
    kind_item:set_generated()
    kind_item:append_text(" (Numeric)")
end
```

### 설계 고민
파생 값을 별도 필드로 추가할지, 기존 필드에 텍스트로 추가할지 선택해야 합니다.

**옵션 1: 별도 필드로 추가 + set_generated()**
```lua
tree:add(f.command_code, buffer(offset, 4))
tree:add(f.command_name, command_name):set_generated()
```
- ✅ 사용자가 필드로 필터링/검색 가능
- ✅ 읽기 편함
- ❌ 실제 패킷에 없는 데이터를 필드로 표시

**옵션 2: append_text()로 추가**
```lua
local item = tree:add(f.command_code, buffer(offset, 4))
item:append_text(string.format(" (%s)", command_name))
```
- ✅ 패킷 구조가 명확
- ❌ 필터링/검색 불가

---

## 2. ByteArray 인덱싱

### 문제
Lua는 1-based indexing을 사용하지만, ByteArray는 0-based indexing을 사용합니다.

```lua
-- ❌ 잘못된 방법
local barray = tvbuf:range(0, 10):bytes()
local first = barray[1]  -- 실제로는 두 번째 바이트!
local second = barray[2] -- 실제로는 세 번째 바이트!
```

### 이유
ByteArray는 C API를 래핑한 객체이며, C는 0-based indexing을 사용합니다. Wireshark는 이를 그대로 유지했습니다.

### 해결
```lua
-- ✅ 올바른 방법
local barray = tvbuf:range(0, 10):bytes()
local first = barray:get_index(0)   -- 첫 번째 바이트
local second = barray:get_index(1)  -- 두 번째 바이트
```

**권장사항**: 가능하면 ByteArray 대신 `tvbuf:range()`를 직접 사용하세요.

```lua
-- 더 좋은 방법
local first = tvbuf:range(0, 1):uint()
local second = tvbuf:range(1, 1):uint()
```

---

## 3. Endianness 불일치

### 문제
값을 읽을 때와 tree에 추가할 때 endianness가 일치하지 않으면, GUI에 잘못된 값이 표시됩니다.

```lua
-- ❌ 잘못된 예
local value = tvbuf:range(0, 4):le_uint()  -- Little-endian으로 읽기
tree:add(pf_field, tvbuf:range(0, 4))       -- Big-endian으로 표시!
```

### 결과
- Lua 코드에서 `value`는 올바른 값
- 하지만 Wireshark GUI의 트리에는 잘못된 값(byte swap된 값)이 표시됨

### 이유
`tree:add()`는 기본적으로 big-endian으로 해석합니다. Little-endian 필드는 `tree:add_le()`를 사용해야 합니다.

### 해결
```lua
-- ✅ 올바른 방법
local value = tvbuf:range(0, 4):le_uint()
tree:add_le(pf_field, tvbuf:range(0, 4))
```

**규칙**: 프로토콜이 little-endian이면 모든 곳에 `le_*` 사용

```lua
-- 일관성 유지
local length = tvbuf:range(0, 4):le_uint()
local command = tvbuf:range(4, 4):le_uint()

tree:add_le(pf_length, tvbuf:range(0, 4))
tree:add_le(pf_command, tvbuf:range(4, 4))
```

---

## 4. Tvb 길이 함수들

### 세 가지 함수
```lua
local len1 = tvbuf:len()
local len2 = tvbuf:reported_len()
local len3 = tvbuf:reported_length_remaining()
```

### 차이점

**`len()`**: 현재 캡처된 길이
- Wireshark의 스냅샷 길이 제한에 의해 패킷이 잘렸을 수 있음
- 예: 실제 1500바이트 패킷이지만 96바이트만 캡처된 경우 → `len() = 96`

**`reported_len()`**: 실제 패킷의 전체 길이
- 네트워크에서 전송된 실제 크기
- 예: 위 경우 → `reported_len() = 1500`

**`reported_length_remaining()`**: 남은 길이
- Dissector가 중첩되어 호출될 때 유용
- 상위 dissector가 일부를 이미 파싱한 경우를 고려

### 언제 무엇을 사용할까?

```lua
-- ❌ len() - 패킷이 잘렸을 때 문제 발생
if tvbuf:len() < HEADER_SIZE then
    return  -- 잘린 패킷도 에러 처리됨!
end

-- ✅ reported_length_remaining() - 가장 안전
local pktlen = tvbuf:reported_length_remaining()
if pktlen < HEADER_SIZE then
    pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
    return
end
```

**권장**: 대부분의 경우 `reported_length_remaining()` 사용

---

## 5. append_text vs set_text

### 차이점

**`append_text()`**: 기존 텍스트 뒤에 추가
```lua
tree:add(pf_command, tvbuf:range(0, 4))
-- 표시: "Command: 100"

item:append_text(" (Ping)")
-- 표시: "Command: 100 (Ping)"
```

**`set_text()`**: 전체 텍스트 교체
```lua
tree:add(pf_command, tvbuf:range(0, 4))
-- 표시: "Command: 100"

item:set_text("Ping Command")
-- 표시: "Ping Command"  (원래 값이 사라짐!)
```

### 언제 사용할까?

**`append_text()` 사용 시기**:
- 원래 값을 유지하면서 추가 정보 제공
- 예: 코드에 이름 추가, 플래그 설명 추가

```lua
local cmd_item = tree:add_le(pf_command, tvbuf:range(0, 4))
cmd_item:append_text(string.format(" (%s)", command_name))
-- 결과: "Command: 100 (Ping)"
```

**`set_text()` 사용 시기**:
- 원래 값이 의미 없고 완전히 새로운 표현이 필요한 경우
- 예: 타임스탬프를 사람이 읽을 수 있는 형식으로

```lua
local time_item = tree:add(pf_timestamp, tvbuf:range(0, 8))
time_item:set_text(string.format("Timestamp: %s", os.date("%Y-%m-%d %H:%M:%S", timestamp)))
-- 결과: "Timestamp: 2025-01-15 10:30:45"
```

**권장**: 일반적으로 `append_text()`가 더 안전합니다.

---

## 6. pinfo.visited와 상태 관리

### 핵심 개념
Wireshark는 패킷을 여러 번 파싱합니다:
1. **First pass** (`pinfo.visited == false`): 최초 파싱
2. **Revisit** (`pinfo.visited == true`): 필터링, 재로딩 등으로 재방문

### 규칙
```lua
if not pinfo.visited then
    -- ✅ First pass: 상태 수정 가능
    conv_data.queue[last] = request_data
else
    -- ❌ Revisit: 캐시만 읽기
    return conv_data.matched[pinfo.number]
end
```

**주의**: First pass에만 상태를 수정하고, revisit에서는 캐시된 데이터만 읽어야 합니다.

---

## 7. Conversation API (Request-Response 매칭)

### 용도
TCP 스트림에서 요청과 응답을 매칭할 때 사용합니다.

### 구현 패턴
```lua
-- 1. Conversation 데이터 구조 초기화
local conv = pinfo.conversation
local conv_data = conv[proto]

if not conv_data then
    conv_data = {
        queue = {first = 0, last = -1},  -- FIFO queue
        matched = {}  -- 캐시
    }
end

-- 2. First pass에만 enqueue/dequeue
if not pinfo.visited then
    -- 상태 수정
    conv_data.queue[last] = request_data
end

-- 3. 데이터 저장
conv[proto] = conv_data
```

### 주의사항
- `pinfo.conversation`이 `nil`일 수 있으므로 반드시 체크
- First pass와 revisit 구분 필수
- 캐시를 사용하여 성능 최적화

### Request-Response 매칭 상세

TCP 스트림에서 요청과 응답을 매칭하는 것은 복잡합니다. 여러 요청이 응답을 기다리고 있을 수 있기 때문입니다.

#### 방법 1: FIFO Queue (Pipelined 프로토콜)

```lua
function proto.dissector(tvbuf, pktinfo, root)
    local conv = pktinfo.conversation
    if not conv then return end

    local conv_data = conv[proto]
    if not conv_data then
        conv_data = {
            queue = { first = 0, last = -1 },  -- FIFO queue
            matched = {}  -- 캐시: frame_num -> request_data
        }
    end

    local is_request = (pktinfo.dst_port == SERVER_PORT)

    if is_request then
        -- Request: enqueue
        if not pktinfo.visited then
            local last = conv_data.queue.last + 1
            conv_data.queue.last = last
            conv_data.queue[last] = {
                frame = pktinfo.number,
                command = command_code
            }
        end
    else
        -- Response: dequeue and match
        local request_data = conv_data.matched[pktinfo.number]

        if not request_data and not pktinfo.visited then
            -- First pass: dequeue
            local first = conv_data.queue.first
            if first <= conv_data.queue.last then
                request_data = conv_data.queue[first]
                conv_data.queue[first] = nil
                conv_data.queue.first = first + 1

                -- 캐시에 저장
                conv_data.matched[pktinfo.number] = request_data
            end
        end

        if request_data then
            -- request_data를 사용하여 응답 파싱
            tree:add(pf_request_in, request_data.frame)
        end
    end

    conv[proto] = conv_data
end
```

**장점**: HTTP/2, gRPC 같은 pipelined 프로토콜에 적합
**단점**: 순서가 보장되지 않는 프로토콜에서는 잘못된 매칭 가능

#### 방법 2: Transaction ID (ID 기반 프로토콜)

```lua
if is_request then
    if not pktinfo.visited then
        conv_data.requests[transaction_id] = {
            frame = pktinfo.number,
            command = command_code
        }
    end
else
    local request_data = conv_data.requests[transaction_id]
    if request_data then
        tree:add(pf_request_in, request_data.frame)
    end
end
```

**장점**: 순서 무관, 정확한 매칭
**단점**: 프로토콜이 transaction ID를 제공해야 함

---

## 8. TCP Desegmentation

### 문제
TCP 스트림은 패킷 경계와 프로토콜 메시지 경계가 다릅니다.

### 해결
```lua
-- Step 1: 헤더 길이 확인
if buflen < HEADER_SIZE then
    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
    return  -- ⚠️ 아무것도 반환하지 않음
end

-- Step 2: 전체 길이 계산
local total_len = HEADER_SIZE + payload_len

-- Step 3: 충분한 데이터가 있을 때까지 대기
if buflen < total_len then
    pinfo.desegment_len = total_len - buflen
    return  -- ⚠️ 아무것도 반환하지 않음
end

-- Step 4: 파싱 완료
return total_len  -- ✅ 사용한 바이트 수 반환
```

### 핵심
- Desegmentation 필요 시: `return` (값 없음)
- 파싱 완료 시: `return total_len`

---

## 9. Buffer 읽기

### Endianness
```lua
-- Big-endian (네트워크 바이트 순서)
local value = buffer(offset, 4):uint()
tree:add(field, buffer(offset, 4))

-- Little-endian (x86 바이트 순서)
local value = buffer(offset, 4):le_uint()
tree:add_le(field, buffer(offset, 4))
```

**주의**: `add`와 `add_le`를 일치시켜야 합니다.

### Buffer 인덱싱
```lua
-- ✅ 올바른 방법
buffer(offset, length)

-- ❌ 잘못된 방법 (배열처럼 접근 불가)
buffer[offset]
```

---

## 10. 필드 등록

### 문제
ProtoField를 정의했어도 등록하지 않으면 사용할 수 없습니다.

### 해결
```lua
-- 1. 필드 정의
local my_field = ProtoField.uint32("proto.field", "Field Name")

-- 2. 등록 (필수!)
iggy.fields = { my_field, ... }  -- 배열로 등록
```

### 중첩 구조 처리
```lua
-- 중첩된 테이블에서 ProtoField 재귀적으로 수집
local function collect_fields(tbl, result)
    for _, value in pairs(tbl) do
        if type(value) == "table" then
            collect_fields(value, result)  -- 재귀
        else
            table.insert(result, value)  -- ProtoField 추가
        end
    end
end
```

---

## 11. 에러 핸들링

### pcall 사용
```lua
local status, err = pcall(function()
    -- 파싱 로직
    tree:add_le(field, buffer(offset, 4))
end)

if not status then
    -- 에러 발생 시 Expert Info 표시
    tree:add_proto_expert_info(ef_dissection_error,
        string.format("Error: %s", err))
    pinfo.cols.info:set("Dissection error")
    return buflen
end
```

**이유**: Lua 에러가 발생하면 Wireshark가 멈추지 않도록 보호합니다.

---

## 12. 조건부 필드 파싱

### 상황
필드 값에 따라 파싱 방법이 달라지는 경우

### 예시: stream_id_kind
```lua
local stream_id_kind = buffer(offset, 1):uint()
offset = offset + 1

local stream_id_length = buffer(offset, 1):uint()
offset = offset + 1

-- kind에 따라 다른 필드 사용
if stream_id_kind == 1 then
    -- Numeric ID
    tree:add_le(f.stream_id_value_numeric, buffer(offset, stream_id_length))
elseif stream_id_kind == 2 then
    -- String ID
    tree:add(f.stream_id_value_string, buffer(offset, stream_id_length))
end

offset = offset + stream_id_length
```

**주의**:
- 두 필드 모두 `ProtoField`로 정의해야 함
- 조건에 맞는 필드만 tree에 추가

---

## 13. Preference 설정

### 정의
```lua
iggy.prefs.server_port = Pref.uint("Server Port", 8090, "Description")
```

### 동적 포트 변경
```lua
function iggy.prefs_changed()
    local tcp_port = DissectorTable.get("tcp.port")

    -- 이전 포트 제거
    if current_port > 0 then
        tcp_port:remove(current_port, iggy)
    end

    -- 새 포트 등록
    tcp_port:add(iggy.prefs.server_port, iggy)
    current_port = iggy.prefs.server_port
end
```

**주의**: Preference 변경 시 포트 재등록 필요

---

## 14. Command Registry 패턴

### 구조
```lua
local COMMANDS = {
    [command_code] = {
        name = "command_name",
        fields = {
            request = { /* ProtoField들 */ },
            response = { /* ProtoField들 */ }
        },
        request_payload_dissector = function(self, buffer, tree, offset)
            -- 요청 파싱
        end,
        response_payload_dissector = function(self, buffer, tree, offset)
            -- 응답 파싱
        end,
    },
}
```

### 장점
- 새 커맨드 추가가 쉬움
- 필드와 파싱 로직이 함께 관리됨
- 타입 체크 가능 (assert 사용)

### 검증
```lua
for code, cmd in pairs(COMMANDS) do
    assert(type(code) == "number", "Command code must be number")
    assert(type(cmd.name) == "string", "Command name must be string")
    assert(type(cmd.request_payload_dissector) == "function", "...")
    assert(type(cmd.response_payload_dissector) == "function", "...")
end
```

---

## 참고 자료
- Wireshark Lua API: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
- 프로젝트 dissector 예시: `wireshark/dissector.lua`
