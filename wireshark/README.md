# 프로젝트 사용 시 알아야 할 거

다음과 같은 요구사항 필요

- iggy 프로젝트 (클론 된 거)
- wireshark 4.6.0 이상

프로젝트 실행 법
1. `cargo run --bin iggy-server -- --with-default-root-credentials` 로 서버 실행 - 포트도 기본 설정 사용
    - 이 테스트 시 실제로 토픽이나 등등을 추가하는데, 이게 문제가 될 수 있음.
2. 서버 실행 이후 테스트코드 실행 `cargo test -p wireshark --features protocol-tests`

wireshark로 쓰고 싶다면?
`./wireshark/dissector.lua` 코드를 플러그인 위치로 두고, wireshark의 플러그인을 재로딩.

```
cp ./wireshark/dissector.lua ~/.local/lib/wireshark/plugins/
rm ~/.local/lib/wireshark/plugins/dissector.lua
```

이유는 모르겠지만 간헐적으로 동일한 프로토콜 정의가 2개가 있다고 에러가 발생하는 경우가 종종 있음.

그런 경우 복사한 `dissector.lua`를 지우고, 다시 실행해보면 될 것.

아무튼 이렇게 wireshark를 키고, 데모 코드를 실행하거나 테스트코드를 실행해보면 잘 인식할거임.


