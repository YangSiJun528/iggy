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

## 14. Enum 값 표시

### 문제
숫자 코드를 사람이 읽을 수 있는 이름으로 표시하고 싶습니다.

### 해결 방법 1: ProtoField에 값 매핑

```lua
-- 1. 값 -> 이름 매핑 테이블
local command_names = {
    [1] = "Ping",
    [2] = "GetStream",
    [3] = "CreateTopic",
}

-- 2. ProtoField 정의 시 매핑 전달
local pf_command = ProtoField.uint32("proto.command", "Command",
                                      base.DEC, command_names)

-- 3. 사용
tree:add_le(pf_command, tvbuf:range(0, 4))
-- GUI에 "Command: 1 (Ping)" 표시
```

**장점**:
- 자동으로 이름이 표시됨
- 필터에서 이름 사용 가능: `proto.command == "Ping"`

### 해결 방법 2: append_text

```lua
local COMMANDS = { [1] = "Ping", [2] = "GetStream" }

local cmd = tvbuf:range(0, 4):le_uint()
local cmd_item = tree:add_le(pf_command, tvbuf:range(0, 4))

if COMMANDS[cmd] then
    cmd_item:append_text(string.format(" (%s)", COMMANDS[cmd]))
end
```

**장점**: 더 세밀한 제어 가능

### 헬퍼 함수 패턴

반복되는 enum 처리를 간소화:

```lua
-- Enum 정의
local RequestType = {
    DISPLAY = 1,
    LED = 2,
}

-- 자동으로 역방향 매핑 생성
local RequestType_names = {}
for name, value in pairs(RequestType) do
    RequestType_names[value] = name
end

-- ProtoField 정의
local pf_type = ProtoField.uint8("proto.type", "Type",
                                  base.HEX, RequestType_names)

-- 코드에서 사용
if type == RequestType.DISPLAY then
    -- ...
end
```

---

## 15. ProtoField.framenum - Request/Response 연결

### 용도
Request와 Response를 GUI에서 클릭 가능한 링크로 연결합니다.

### 사용법

```lua
-- 1. ProtoField 정의
local pf_request_in = ProtoField.framenum("proto.request", "Request",
                                          base.NONE, frametype.REQUEST)
local pf_response_in = ProtoField.framenum("proto.response", "Response",
                                           base.NONE, frametype.RESPONSE)

-- 2. 등록
proto.fields = { pf_request_in, pf_response_in }

-- 3. Request/Response 매칭 후 사용
if is_request then
    -- Request 패킷에서
    if matched_response_frame then
        tree:add(pf_response_in, matched_response_frame)
    end
else
    -- Response 패킷에서
    if matched_request_frame then
        tree:add(pf_request_in, matched_request_frame)
    end
end
```

### 효과
- Wireshark GUI에서 클릭 가능한 링크로 표시됨
- 해당 프레임으로 바로 이동 가능
- 사용자 경험 향상

### Conversation 데이터와 함께 사용

```lua
local id2frame = {
    request = {},   -- request_id -> frame_number
    response = {},  -- request_id -> frame_number
}

if is_request then
    if not pktinfo.visited then
        id2frame.request[request_id] = pktinfo.number
    end

    if id2frame.response[request_id] then
        tree:add(pf_response_in, id2frame.response[request_id])
    end
else
    if not pktinfo.visited then
        id2frame.response[request_id] = pktinfo.number
    end

    if id2frame.request[request_id] then
        tree:add(pf_request_in, id2frame.request[request_id])
    end
end
```

---

## 16. Desegmentation 헬퍼 패턴

### 문제
TCP desegmentation 로직이 복잡하고 반복적입니다.

### 해결: msg_consumer 패턴

```lua
local function msg_consumer(buf, pinfo)
    local obj = {
        msg_offset = 0,   -- 현재 메시지 시작 위치
        msg_taken = 0,    -- 현재 메시지에서 읽은 바이트
        not_enough = false,
    }

    obj.next_msg = function()
        obj.msg_offset = obj.msg_offset + obj.msg_taken
        obj.msg_taken = 0
    end

    obj.take_next = function(n)
        if obj.not_enough then
            return  -- 이미 부족한 상태
        end

        local remaining = buf:len() - (obj.msg_offset + obj.msg_taken)
        if remaining < n then
            pinfo.desegment_offset = obj.msg_offset
            pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            obj.not_enough = true
            return
        end

        local data = buf:range(obj.msg_offset + obj.msg_taken, n)
        obj.msg_taken = obj.msg_taken + n
        return data
    end

    obj.current_msg_buf = function()
        return buf:range(obj.msg_offset, obj.msg_taken)
    end

    return obj
end
```

### 사용 예시

```lua
function proto.dissector(buf, pinfo, root)
    local consumer = msg_consumer(buf, pinfo)

    while true do
        consumer.next_msg()

        -- 헤더 읽기
        local id_buf = consumer.take_next(4)
        if not id_buf then
            return  -- 데이터 부족
        end

        local type_buf = consumer.take_next(1)
        if not type_buf then
            return
        end

        -- 동적 길이 필드
        local len = type_buf:le_uint()
        local data_buf = consumer.take_next(len)
        if not data_buf then
            return
        end

        -- Tree에 추가
        local tree = root:add(proto, consumer.current_msg_buf())
        tree:add_le(pf_id, id_buf)
        tree:add_le(pf_type, type_buf)
        tree:add(pf_data, data_buf)
    end
end
```

### 장점
- Desegmentation 로직이 캡슐화됨
- 에러 처리가 간단해짐
- 코드 가독성 향상

---

## 17. Deferred Tree Adding

### 문제
파싱 중 오류가 발생하면 이미 tree에 추가된 필드들이 불완전한 상태로 남습니다.

### 해결: 검증 후 tree 추가

```lua
function proto.dissector(buf, pinfo, root)
    -- 1. 파싱할 필드들을 임시 테이블에 저장
    local tree_add = {}

    -- 2. 모든 필드 파싱
    local id_buf = consumer.take_next(4)
    if not id_buf then
        return
    end
    table.insert(tree_add, {pf_id, id_buf})

    local type_buf = consumer.take_next(1)
    if not type_buf then
        return
    end
    table.insert(tree_add, {pf_type, type_buf})

    local data_buf = consumer.take_next(10)
    if not data_buf then
        return
    end
    table.insert(tree_add, {pf_data, data_buf})

    -- 3. 모든 파싱이 성공한 후 tree에 추가
    local tree = root:add(proto, consumer.current_msg_buf())
    for _, item in ipairs(tree_add) do
        tree:add_le(item[1], item[2])
    end
end
```

### 장점
- Desegmentation 시 부분 파싱된 트리가 표시되지 않음
- 오류 발생 시 깔끔한 처리
- 원자적 파싱 보장

### 주의사항
- 메모리 사용량이 약간 증가
- 간단한 프로토콜에서는 불필요할 수 있음

---

## 18. 필드 이름 헬퍼 함수

### 문제
모든 ProtoField에 프로토콜 prefix를 반복해서 작성해야 합니다.

```lua
-- 반복적인 코드
local pf_id = ProtoField.uint32("myproto.id", "ID")
local pf_command = ProtoField.uint32("myproto.command", "Command")
local pf_length = ProtoField.uint32("myproto.length", "Length")
```

### 해결: 헬퍼 함수

```lua
local proto = Proto("myproto", "My Protocol")

-- 헬퍼 함수
local function field(name)
    return string.format("%s.%s", proto.name, name)
end

-- 간결한 정의
local pf_id = ProtoField.uint32(field("id"), "ID")
local pf_command = ProtoField.uint32(field("command"), "Command")
local pf_length = ProtoField.uint32(field("length"), "Length")

-- 중첩 필드
local pf_header_version = ProtoField.uint8(field("header.version"), "Version")
```

### 장점
- 타이핑 감소
- 오타 방지
- 프로토콜 이름 변경 시 한 곳만 수정

### 테이블 방식으로 더 개선

```lua
local fields = {
    id = ProtoField.uint32(field("id"), "ID"),
    command = ProtoField.uint32(field("command"), "Command"),
    length = ProtoField.uint32(field("length"), "Length"),
}

-- 자동 등록
for _, pf in pairs(fields) do
    table.insert(proto.fields, pf)
end

-- 사용
tree:add_le(fields.id, buf:range(0, 4))
tree:add_le(fields.command, buf:range(4, 4))
```

---

## 19. Command Registry 패턴

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
