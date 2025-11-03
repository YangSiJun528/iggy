# 문제상황 정리

1. iggy 서버 실행 시 `--with-default-root-credentials` flags가 약간 햇갈림.
   - 이건 iggy/iggy 인증 정보를 설정함 (id/pw)
2. local_data가 없어야 root 정보를 수행하는데, 그 설명이 없어서 좀 햇갈림. 아래 CLI 문구 참고.
3. 그리고 CLI help 설명을 보면 경고한다는데, 경고 로그도 없음.
   - 로직 까보기도 했고, `RUST_LOG=trace`로 설정하고 서버 재시작해도 동일함.
   - core/server/src/main.rs:110

**3번 문제 원인:**
- CLI help: "If the **root user already exists**, this flag has no effect and a warning will be printed."
- 실제 코드: **환경 변수**(`IGGY_ROOT_USERNAME`, `IGGY_ROOT_PASSWORD`)가 이미 설정되어 있는지만 체크
- 즉, root user가 데이터베이스(local_data)에 실제로 존재하는지는 확인하지 않음
- 따라서 local_data가 있어도 환경 변수가 없으면 경고가 출력되지 않음
- CLI 문서와 실제 동작이 불일치함

```
      --with-default-root-credentials
          Use default root credentials (INSECURE - FOR DEVELOPMENT ONLY!)
          
          When this flag is set, the root user will be created with username 'iggy'
          and password 'iggy' if it doesn't exist. If the root user already exists, 
          this flag has no effect and a warning will be printed. << 여기 말과는 달리 warning 출력 안됨.
          
          This flag is equivalent to setting IGGY_ROOT_USERNAME=iggy and IGGY_ROOT_PASSWORD=iggy,
          but environment variables take precedence over this flag.
          
          WARNING: This is insecure and should only be used for development and testing!
          
          Examples:
            iggy-server --with-default-root-credentials     # Use 'iggy/iggy' as root credentials
```


# 사용하는 명령어

flag 설정: `cargo run --bin iggy-server -- --with-default-root-credentials`
그냥 실행: `cargo run --bin iggy-server`
기본 인증 설정 사용하는 데모 예시: `cargo run --example getting-started-producer`, `cargo run --example getting-started-consumer`

# TODO

일단 README 문구 수정해서 올리기. (local_data에 대한 설명, 처음 실행 시 root credentials이 생긴다는거. 웹사이트 문서 참고)

CLI 문구 수정하고, 이슈에 적은 info 로그에도 만약 기존 Root 정보가 남아있다면 재사용된다고 적어서 PR 한번에 올릴지 문서/코드 분리할지는 물어보기.

근데 코드 수정하고 문구를 보완한다는 느낌이면 하나도 될 듯? 이건 다른 PR들 내역 보고 결정 ㄱㄱ
