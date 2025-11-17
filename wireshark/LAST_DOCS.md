# IGGY 프로토콜 분석을 위한 노트

구현은 기존 구현 참고

프로토콜에 쓰이는 요청/응답의 바이너리 형식을 분석해야 하는데, 문서가 없으므로 코드를 분석해야 한다.

요청/응답의 공통적인 모델은 이미 구현되어있으므로 스킵. 구체적인 Payload를 구하는 법만 알면 된다.

## 요청 Payload

`core/common/src/commands/**/*.rs` 파일들을 참고한다.

각 command struct는 `BytesSerializable` trait을 구현하고 있다. (여러 command struct에서 사용하는 공통 데이터 struct도 `BytesSerializable`를 구현한다.)
- `to_bytes()`: struct를 바이너리로 직렬화
- `from_bytes()`: 바이너리를 struct로 역직렬화

예시:
- `commands/system/ping.rs`: payload 없음
- `commands/users/login_user.rs:82-110`: username(가변) + password(가변) + version(가변) + context(가변)
- `commands/streams/get_stream.rs:50-63`: Identifier 하나
- `commands/messages/poll_messages.rs:138-206`: Consumer + stream_id + topic_id + partition_id + strategy + count + auto_commit

`to_bytes()` 메서드를 보면 필드를 순서대로 write하는 것을 볼 수 있다. 이 순서대로 파싱하면 된다.

## 응답 Payload

응답 헤더에는 command code가 없다. 응답은 `BytesSerializable` trait을 사용하지 않는다.

각 command의 클라이언트 구현에서 어떤 mapper 함수를 호출하는지 확인한다:
- `core/binary_protocol/src/client/binary_system/mod.rs`
- `core/binary_protocol/src/client/binary_streams/mod.rs`
- `core/binary_protocol/src/client/binary_users/mod.rs`
- `core/binary_protocol/src/client/binary_messages/mod.rs`

예: `login_user()` 메서드는 `mapper::map_identity_info()`를 호출한다.

mapper 함수 구현은 `core/binary_protocol/src/utils/mapper.rs`에 있다.
- 서버용 mapper(`core/server/src/binary/mapper.rs`)는 응답 생성용이므로 참고하지 않는다. 
- 클라이언트용 mapper가 바이너리를 직접 파싱하는 로직을 담고 있기 때문이다.

mapper 함수 예시 (모두 `core/binary_protocol/src/utils/mapper.rs`):
- `map_identity_info()` (line 455-465): user_id(4B) 하나만
- `map_stream()` (line 552-573): 고정 32B + name(가변) + topics(반복)
- `map_stats()` (line 37-350): 고정 108B + 가변 문자열들 + cache_metrics(반복)

## 요청-응답 매핑

TODO: IGGY는 그 뭐였나 카프카 어쩌구 그거 기억이 안나네 여기에 쓰기

## 공통 타입

자주 나오는 타입들:

Identifier: kind(1B) + length(1B) + value
- `core/common/src/types/identifier/mod.rs:216-247`
Consumer: kind(1B) + identifier
- `core/common/src/types/consumer/consumer_kind.rs:95-118`
PollingStrategy: kind(1B) + value(8B)
- `core/common/src/types/message/polling_strategy.rs`
Partitioning: kind(1B) + length(1B) + value
- `core/common/src/types/message/partitioning.rs:36-149`

## 바이트 순서

모든 정수는 little-endian이다.

가변 필드 패턴:
- 짧은 문자열: length(1B) + data
- 긴 문자열: length(4B) + data
- optional: length가 0이면 None
- 반복: count(4B) + entries
