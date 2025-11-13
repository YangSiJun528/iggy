# Wireshark Lua API 레퍼런스

Wireshark Lua dissector 작성 시 자주 사용하는 핵심 API 사용법을 정리한 문서입니다.

## 목차
1. [Proto - 프로토콜 정의](#1-proto---프로토콜-정의)
2. [Tvb - 패킷 버퍼](#2-tvb---패킷-버퍼)
3. [Pinfo - 패킷 정보](#3-pinfo---패킷-정보)
4. [TreeItem - 트리 아이템](#4-treeitem---트리-아이템)
5. [참고 자료](#5-참고-자료)

---

## 1. Proto - 프로토콜 정의

**참고**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_Proto

### 1.1 기본 생성

```lua
-- Proto(name, description)
local mydns = Proto("mydns", "MyDNS Protocol")
```

**매개변수**:
- `name`: 프로토콜 약어 (소문자, 필터에 사용됨)
- `description`: 사용자에게 표시될 전체 이름

### 1.2 필드 등록

```lua
-- ProtoField 정의
local pf_transaction_id = ProtoField.uint16("mydns.trans_id", "Transaction ID")
local pf_flags = ProtoField.uint16("mydns.flags", "Flags", base.HEX)
local pf_name = ProtoField.string("mydns.name", "Name")

-- Enum 값 표시 (값 -> 이름 매핑)
local cmd_names = { [1] = "Ping", [2] = "GetStream", [3] = "CreateTopic" }
local pf_command = ProtoField.uint32("mydns.command", "Command", base.DEC, cmd_names)

-- Request/Response 프레임 참조
local pf_request = ProtoField.framenum("mydns.request", "Request", base.NONE, frametype.REQUEST)

-- proto.fields에 배열로 등록
mydns.fields = { pf_transaction_id, pf_flags, pf_name, pf_command, pf_request }
```

**주의**: 등록하지 않은 ProtoField는 사용 불가

### 1.3 Dissector 함수

```lua
function mydns.dissector(tvbuf, pktinfo, root)
    pktinfo.cols.protocol:set("MYDNS")

    local tree = root:add(mydns, tvbuf:range(0, tvbuf:len()))
    tree:add(pf_transaction_id, tvbuf:range(0, 2))

    return tvbuf:len()  -- 파싱한 바이트 수 반환
end
```

**매개변수**: `(tvbuf: Tvb, pktinfo: Pinfo, root: TreeItem)`
**반환값**: 파싱한 바이트 수 (number) 또는 nil

**주의**: Desegmentation 중에는 반환하지 않음

### 1.4 Preference 설정

```lua
-- Preference 정의
mydns.prefs.port = Pref.uint("Port number", 8090, "Description")
mydns.prefs.debug = Pref.bool("Debug", false, "Enable debug")

-- 변경 시 콜백
function mydns.prefs_changed()
    local tcp_table = DissectorTable.get("tcp.port")
    tcp_table:remove(old_port, mydns)
    tcp_table:add(mydns.prefs.port, mydns)
    old_port = mydns.prefs.port
end
```

### 1.5 Expert Info

```lua
-- 정의
local ef_error = ProtoExpert.new("mydns.error", "Error",
                                  expert.group.MALFORMED,
                                  expert.severity.ERROR)

-- 등록
mydns.experts = { ef_error }

-- 사용
tree:add_proto_expert_info(ef_error, "Error message")
```

### 1.6 프로토콜 등록

```lua
-- 포트 기반 등록
DissectorTable.get("tcp.port"):add(8090, mydns)

-- Heuristic dissector
function heur_dissect(tvbuf, pktinfo, root)
    if is_my_protocol(tvbuf) then
        mydns.dissector(tvbuf, pktinfo, root)
        return true
    end
    return false
end
mydns:register_heuristic("tcp", heur_dissect)
```

---

## 2. Tvb - 패킷 버퍼

**참고**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb

### 2.1 길이 확인

```lua
local len = tvbuf:len()                              -- 캡처된 길이
local reported = tvbuf:reported_len()                -- 실제 패킷 길이
local remaining = tvbuf:reported_length_remaining()  -- 남은 길이
```

**주의**: 패킷이 잘린 경우 `len() < reported_len()`

### 2.2 범위 지정

```lua
local range = tvbuf:range(0, 4)    -- offset 0, length 4
local range = tvbuf(4, 2)          -- offset 4, length 2 (단축)
local all = tvbuf:range()          -- 전체
```

### 2.3 값 읽기

```lua
-- Unsigned integer
local u32 = tvbuf:range(0, 4):uint()       -- Big-endian
local u32 = tvbuf:range(0, 4):le_uint()    -- Little-endian

-- Signed integer
local i32 = tvbuf:range(0, 4):int()        -- Big-endian
local i32 = tvbuf:range(0, 4):le_int()     -- Little-endian

-- 기타
local u64 = tvbuf:range(0, 8):uint64()     -- uint64
local str = tvbuf:range(0, 10):string()    -- string
local bytes = tvbuf:range(0, 10):bytes()   -- ByteArray
```

**주의**: Endianness를 올바르게 지정해야 함

### 2.4 ByteArray

```lua
local barray = tvbuf:range(0, 10):bytes()
local byte = barray:get_index(0)         -- 0-based indexing
local raw = barray:raw(0, 5)             -- raw string
```

**주의**: ByteArray는 0-based, Lua table은 1-based

---

## 3. Pinfo - 패킷 정보

**참고**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo

### 3.1 컬럼 조작

```lua
pktinfo.cols.protocol:set("MYDNS")
pktinfo.cols.info:set("Query")
pktinfo.cols.info:append(" - example.com")
pktinfo.cols.info:prepend("Request: ")
```

### 3.2 패킷 정보

```lua
local src_port = pktinfo.src_port
local dst_port = pktinfo.dst_port
local src_addr = pktinfo.src          -- Address
local dst_addr = pktinfo.dst          -- Address
local number = pktinfo.number         -- 프레임 번호
local visited = pktinfo.visited       -- 재방문 여부
```

### 3.3 Conversation

```lua
local conv = pktinfo.conversation
if not conv then return end

local conv_data = conv[proto]
if not conv_data then
    conv_data = { queue = {}, matched = {} }
end

-- First pass에만 상태 수정
if not pktinfo.visited then
    table.insert(conv_data.queue, data)
end

conv[proto] = conv_data
```

**주의**: `pktinfo.visited`로 first pass와 재방문 구분 필수

### 3.4 Desegmentation

```lua
-- TCP 재조립
pktinfo.desegment_offset = 0  -- 메시지 시작 위치
pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
return  -- 더 많은 데이터 대기
```

**주의**: desegment 설정 후 반드시 return (값 없이)

---

## 4. TreeItem - 트리 아이템

**참고**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem

### 4.1 필드 추가

```lua
-- add(protofield, tvbrange, [value])
tree:add(pf_field, tvbuf:range(0, 4))
tree:add(pf_name, tvbuf:range(0, 10), "value")

-- Little-endian
tree:add_le(pf_length, tvbuf:range(0, 4))
```

**주의**: Endianness는 add/add_le와 값 읽기 함수 모두 일치시켜야 함

### 4.2 서브트리

```lua
-- ProtoField로 서브트리
local subtree = tree:add(pf_header, tvbuf:range(0, 10))
subtree:add(pf_field1, tvbuf:range(0, 4))
subtree:add(pf_field2, tvbuf:range(4, 4))

-- 텍스트로 서브트리
local section = tree:add("Section Name")
section:add(pf_item, tvbuf:range(0, 4))
```

### 4.3 텍스트 조작

```lua
local item = tree:add(pf_field, tvbuf:range(0, 4))

item:append_text(" (info)")
item:prepend_text("Prefix: ")
item:set_text("New text")
```

### 4.4 Generated 필드

```lua
-- 패킷에 없는 파생 값 표시
tree:add(pf_name, name):set_generated()
```

### 4.5 Expert Info

```lua
tree:add_proto_expert_info(ef_error, "Error message")
tree:add_tvb_expert_info(ef_warn, tvbuf:range(0, 4), "Warning")
```

### 4.6 Bit 필드

```lua
-- ProtoField 정의
local pf_flag = ProtoField.bool("proto.flag", "Flag", 16, nil, 0x8000)

-- 사용
tree:add(pf_flag, tvbuf:range(0, 2))  -- 0x8000 비트만 추출
```

---

## 5. 참고 자료

- **Wireshark Lua API**: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html
- **Proto**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_Proto
- **Tvb**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html#lua_class_Tvb
- **Pinfo**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html#lua_class_Pinfo
- **TreeItem**: https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html#lua_class_TreeItem
- **공식 예제**: https://gitlab.com/wireshark/wireshark/-/tree/master/test/lua
