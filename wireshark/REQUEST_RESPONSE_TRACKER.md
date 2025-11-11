# Request-Response Tracker 개요

## 해결하려는 문제

Iggy 프로토콜은 **파이프라이닝**을 지원합니다. 클라이언트가 응답을 기다리지 않고 여러 요청을 연속으로 보낼 수 있습니다:

```
Client → Server:  LoginUser → CreateTopic → Ping
Client ← Server:              LoginUser OK ← CreateTopic OK ← Ping OK
```

Wireshark에서 응답 패킷을 dissect할 때, **이 응답이 어떤 요청에 대한 것인지** 알아야 올바르게 파싱할 수 있습니다.

응답 패킷 자체에는 명령어 정보가 없으므로, 요청과 매칭해야 합니다.

## 핵심 요구사항

### 1. FIFO 매칭

Iggy는 응답을 요청 순서대로 보냅니다:
```
REQ1 → REQ2 → REQ3
     RESP1 ← RESP2 ← RESP3
```

→ **Queue(FIFO)로 해결**

### 2. Wireshark Multi-pass

Wireshark는 패킷을 여러 번 dissect합니다:
- **Pass 1**: 파일 열 때 (모든 패킷)
- **Pass 2+**: 사용자 클릭, 필터 적용 (일부 패킷만)

**문제:** Pass 2에서 응답만 dissect되면 queue가 비어있음

→ **pinfo.visited + 캐싱으로 해결**

### 3. 다중 연결 독립성

여러 클라이언트가 동시 연결 시 각각 독립적으로 추적 필요

→ **Conversation API로 해결**

## 구현 방식 비교

### 레거시: 전역 테이블 + 프레임 번호 기반

```lua
local stream_requests = {}  -- [tcp_stream][frame] = cmd
local stream_responses = {} -- [tcp_stream][resp_frame] = req_frame

-- 응답 매칭: 모든 요청 순회하며 "가장 최근 매칭 안된 요청" 찾기
for req_frame, req_data in pairs(stream_requests[stream_id]) do
    if req_frame < resp_frame and not already_matched(req_frame) then
        -- O(n×m) 복잡도
    end
end
```

**왜 나빴나:**
- 복잡한 역방향 검색 로직 (O(n×m)) - 이건 queue 썼으면 해결 되었을수도?
- `tcp.stream` 필드 수동 추출 필요
- `init()` 함수에서 수동 메모리 정리
- 전역 상태로 인한 디버깅 어려움

### 현재: Conversation API + Queue

```lua
local conv = pinfo.conversation  -- Wireshark가 제공
conv[iggy] = {queue = {first=0, last=-1}, matched = {}}

-- 응답 매칭: queue에서 pop (O(1))
command = table.remove(queue, 1)
```

**왜 좋은가:**
- 단순한 FIFO queue (O(1))
- Wireshark가 연결 관리 + 메모리 자동 정리
- 공식 API 사용

## 동작 방식

```lua
-- Pass 1 (pinfo.visited = false)
if is_request then
    enqueue(command_code)  -- queue에 추가
end

if is_response then
    command = dequeue()     -- queue에서 꺼냄
    matched[frame] = command  -- 캐싱
end

-- Pass 2+ (pinfo.visited = true)
if is_response then
    command = matched[frame]  -- 캐시 조회만
    -- queue 건드리지 않음
end
```

## Conversation API 장점

1. **자동 연결 관리**: `pinfo.conversation`로 TCP 연결별 객체 자동 제공
2. **자동 메모리 정리**: TCP 종료 시 Wireshark가 자동 삭제
3. **공식 API**: Wireshark 4.6+에서 정식 지원

## 캐시 메모리 이슈

**문제:**

```lua
matched = {
    [45] = 38,    -- Frame 45 → LoginUser
    [47] = 302,   -- Frame 47 → CreateTopic
    [50] = 1,     -- Frame 50 → Ping
    ...           -- 응답 개수만큼 계속 증가
}
```

- 캐시가 무한정 증가 (응답마다 캐싱)
- 긴 세션에서 메모리 사용량 누적

**해결 방안:**

1. **현실적으로 문제 없음**
   - 일반적인 세션: 수백~수천 개 응답
   - 메모리: frame_number(8byte) + command(작음) × 개수
   - 예: 10,000 응답 = ~100KB

2. **필요시 개선**
   ```lua
   -- 옵션 1: LRU 캐시 (최근 N개만 유지)
   -- 옵션 2: 주기적 정리 (오래된 항목 삭제)
   ```

3. **Wireshark 특성상 안전**
   - TCP 연결 종료 시 전체 정리됨
   - pcap 파일은 일반적으로 유한함

## 제약 사항

1. **Wireshark 4.6+ 필요**
2. **FIFO 순서 보장 필요** (Out-of-order 응답 불가)
3. **긴 세션 시 캐시 메모리 증가** (일반적으로 무시 가능)

## 참고

- [Conversation API MR #18890](https://gitlab.com/wireshark/wireshark/-/merge_requests/18890)
- [Programming in Lua - Queue](http://www.lua.org/pil/11.4.html)
