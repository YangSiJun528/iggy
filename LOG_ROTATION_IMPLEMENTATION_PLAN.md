# Log Rotation 구현 계획 (Custom Implementation)

## 결정사항: tracing-rolling-file을 Iggy 프로젝트로 Vendoring

### 근거
Iggy 코드베이스 분석 결과, 유사한 패턴들이 이미 존재:
1. ✅ **Segment rotation pattern** - 크기 기반 rotation (segment.rs)
2. ✅ **Offset-based file naming** - 순차 파일명 생성
3. ✅ **Periodic cleanup task** - message_cleaner 패턴
4. ✅ **IggyTimestamp utilities** - 타임스탬프 포맷팅

→ **tracing-rolling-file (692줄) 코드를 복사해서 수정하는 것이 최선**

---

## 구현 방식

### A. tracing-rolling-file Vendoring

**새 모듈 생성**: `core/server/src/log/rolling_file/`

```
core/server/src/log/
├── logger.rs
├── runtime.rs
└── rolling_file/          # 신규
    ├── mod.rs             # tracing-rolling-file의 lib.rs 복사
    ├── base.rs            # tracing-rolling-file의 base.rs 복사
    └── condition.rs       # 커스텀 rotation 조건
```

**라이선스**: tracing-rolling-file도 MIT/Apache-2.0 → Iggy와 호환 ✅

---

### B. 커스터마이징 포인트

#### 1. **파일명 형식 - 혼합 방식**

**시간 기반 rotation**:
```
iggy-server.log.2025-11-25-14
iggy-server.log.2025-11-25-15
```

**크기 기반 rotation** (같은 시간 내):
```
iggy-server.log.2025-11-25-14
iggy-server.log.2025-11-25-14.1  // 512MB 초과
iggy-server.log.2025-11-25-14.2  // 또 초과
```

**구현**:
```rust
// rolling_file/mod.rs 수정
fn get_rotated_filename(&self, rotation_type: RotationType) -> String {
    match rotation_type {
        RotationType::Time => {
            let timestamp = IggyTimestamp::now();
            format!("{}.{}",
                self.base_filename,
                timestamp.to_utc_string("%Y-%m-%d-%H"))
        }
        RotationType::Size { sequence } => {
            format!("{}.{}.{}",
                self.current_time_file,
                sequence)
        }
    }
}
```

#### 2. **Rotation Hook 추가**

```rust
pub struct RollingFileAppender {
    // ... 기존 필드들
    on_rotation: Option<Box<dyn Fn() + Send>>,  // 신규
}

impl RollingFileAppender {
    pub fn with_rotation_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn() + Send + 'static
    {
        self.on_rotation = Some(Box::new(callback));
        self
    }

    fn rollover(&mut self) -> io::Result<()> {
        // ... 기존 rotation 로직

        // Hook 호출
        if let Some(ref callback) = self.on_rotation {
            callback();
        }

        Ok(())
    }
}
```

#### 3. **Retention Cleanup**

**Rotation hook에서 cleanup 트리거**:
```rust
let file_appender = RollingFileAppender::builder()
    .filename(logs_path.join("iggy-server.log"))
    .condition_hourly()
    .condition_max_file_size(config.max_size.as_bytes_u64())
    .with_rotation_callback(move || {
        // Rotation 발생 시 비동기로 cleanup 실행
        let logs_path = logs_path.clone();
        let retention = config.retention.get_duration();
        compio::runtime::spawn(async move {
            cleanup_old_logs(&logs_path, retention).await;
        });
    })
    .build()?;
```

**Cleanup 함수** (message_cleaner 패턴 참고):
```rust
async fn cleanup_old_logs(logs_path: &PathBuf, retention: Duration) -> Result<(), LogError> {
    let cutoff = IggyTimestamp::now()
        .0
        .checked_sub(retention)
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let entries = std::fs::read_dir(logs_path)?;
    let mut deleted = 0;

    for entry in entries.flatten() {
        let filename = entry.file_name();
        let filename_str = filename.to_string_lossy();

        // iggy-server.log로 시작하는 파일만
        if !filename_str.starts_with("iggy-server.log") {
            continue;
        }

        // 현재 active 파일은 제외
        if filename_str == "iggy-server.log" {
            continue;
        }

        if let Ok(metadata) = entry.metadata() {
            if let Ok(modified) = metadata.modified() {
                if modified < cutoff {
                    // compio로 비동기 삭제
                    let _ = compio::fs::remove_file(entry.path()).await;
                    deleted += 1;
                }
            }
        }
    }

    if deleted > 0 {
        info!("Cleaned up {} old log files", deleted);
    }

    Ok(())
}
```

---

## 파일별 변경 내역

### 1. 신규 파일

#### `core/server/src/log/rolling_file/mod.rs` (~400줄)
- tracing-rolling-file/src/lib.rs 복사
- 파일명 형식 수정 (timestamp 포함)
- Rotation hook 추가
- Apache license header 추가

#### `core/server/src/log/rolling_file/base.rs` (~300줄)
- tracing-rolling-file/src/base.rs 복사
- Condition 로직은 그대로 유지
- Apache license header 추가

### 2. 수정 파일

#### `core/server/src/log/logger.rs`

**변경 전**:
```rust
let file_appender = tracing_appender::rolling::hourly(logs_path.clone(), IGGY_LOG_FILE_PREFIX);
let (mut non_blocking_file, file_guard) = tracing_appender::non_blocking(file_appender);
```

**변경 후**:
```rust
use crate::log::rolling_file::{RollingFileAppender, RollingCondition};

let logs_path_clone = logs_path.clone();
let retention = config.retention.get_duration();

let file_appender = RollingFileAppender::builder()
    .filename(logs_path.join("iggy-server.log").to_string_lossy().to_string())
    .condition_hourly()
    .condition_max_file_size(config.max_size.as_bytes_u64())
    .with_rotation_callback(move || {
        let path = logs_path_clone.clone();
        let ret = retention;
        compio::runtime::spawn(async move {
            let _ = cleanup_old_logs(&path, ret).await;
        });
    })
    .build()
    .map_err(|_| LogError::FileReloadFailure)?;

// tracing-appender의 non_blocking은 그대로 사용
let (mut non_blocking_file, file_guard) = {
    use std::io::Write;
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    (writer, guard)
};

// cleanup_old_logs 함수 추가 (위 참고)
```

#### `core/server/src/log/mod.rs`
```rust
pub mod logger;
pub mod runtime;
mod rolling_file;  // 신규
```

#### `_install_log_rotation_handler()` 구현
```rust
fn _install_log_rotation_handler(&self) {
    // 구현 완료:
    // - Size-based rotation: rolling_file::RollingFileAppender
    // - Time-based rotation: condition_hourly()
    // - Retention: rotation hook에서 cleanup_old_logs() 호출
}
```

### 3. Cargo.toml (변경 없음!)
외부 의존성 추가 불필요 - vendoring이므로

---

## 동작 흐름

### Rotation 시나리오

**시나리오 1: 시간 도달 (매 시간)**
```
1. 14:59:59 → iggy-server.log (active)
2. 15:00:00 → RollingFileAppender가 시간 변화 감지
3. Rotation 실행:
   - iggy-server.log → iggy-server.log.2025-11-25-14
   - 새로운 iggy-server.log 생성
4. Hook 호출 → cleanup_old_logs() 비동기 실행
5. 7일 넘은 파일들 삭제
```

**시나리오 2: 크기 도달 (512MB)**
```
1. iggy-server.log (500MB)
2. Write 시 512MB 초과 감지
3. Rotation 실행:
   - iggy-server.log → iggy-server.log.2025-11-25-14.1
   - 새로운 iggy-server.log 생성
4. Hook 호출 → cleanup 실행
```

**시나리오 3: 혼합 (시간 + 크기)**
```
14:30 - iggy-server.log (300MB)
14:45 - iggy-server.log (512MB 초과)
      → iggy-server.log.2025-11-25-14.1
14:50 - iggy-server.log (512MB 초과)
      → iggy-server.log.2025-11-25-14.2
15:00 - 시간 변화
      → iggy-server.log.2025-11-25-15
```

---

## 기존 파일 호환성

**현재 로그 파일들** (tracing-appender 생성):
```
iggy-server.log.2025-11-24-09
iggy-server.log.2025-11-24-10
```

**신규 파일 형식**:
```
iggy-server.log.2025-11-25-14     # 시간 rotation
iggy-server.log.2025-11-25-14.1   # 크기 rotation
```

**호환 방식**:
- 둘 다 `iggy-server.log` prefix
- Cleanup은 둘 다 처리 (7일 기준)
- 자연스럽게 공존 → 시간 지나면 정리됨

---

## 테스트 계획

### 1. Unit Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_time_rotation() {
        // 시간 변화 시 rotation 확인
    }

    #[test]
    fn test_size_rotation() {
        // 512MB 도달 시 rotation 확인
    }

    #[test]
    fn test_filename_format() {
        // 파일명 형식 검증
    }

    #[test]
    fn test_retention_cleanup() {
        // 7일 넘은 파일 삭제 확인
    }
}
```

### 2. Integration Tests
- 실제 로그 대량 생성 (512MB 초과)
- 시간 경과 시뮬레이션
- Cleanup 동작 확인

---

## 예상 작업 시간

1. **Vendoring** (1시간)
   - tracing-rolling-file 코드 복사
   - Apache license header 추가
   - 모듈 구조 정리

2. **커스터마이징** (2-3시간)
   - 파일명 형식 수정
   - Rotation hook 추가
   - Cleanup 로직 구현

3. **통합** (1시간)
   - logger.rs 수정
   - 기존 코드와 연결

4. **테스트** (2시간)
   - Unit tests 작성
   - Integration tests
   - 수동 검증

**총 예상: 6-7시간**

---

## 장점

1. ✅ **완전한 통제** - Iggy 팀이 직접 관리
2. ✅ **요구사항 완벽 구현** - 시간 정보 + 크기 rotation + hook
3. ✅ **의존성 없음** - 외부 crate 불필요
4. ✅ **Apache 프로젝트 적합** - 라이선스 호환
5. ✅ **유지보수 용이** - 코드가 프로젝트 내부에 있음
6. ✅ **성능 최적화 가능** - 필요시 Iggy에 맞게 튜닝

## 단점

1. ⚠️ **작업량** - 6-7시간 (vs 외부 crate 2-3시간)
2. ⚠️ **유지보수 책임** - 버그 수정/개선 필요 시 팀 부담
3. ⚠️ **검증 필요** - 새 코드라 철저한 테스트 필요

---

## 최종 권장

**이 방식을 추천합니다!**

이유:
1. Iggy는 고성능 시스템 → 로깅도 최적화 필요
2. Apache 재단 프로젝트 → 의존성 최소화 선호
3. 요구사항이 명확 → Custom이 더 적합
4. 코드 복잡도 낮음 → 692줄로 관리 가능
5. 장기적으로 더 나음 → 완전한 통제

---

## 대안 분석 및 선택 근거

### 검토했던 다른 옵션들

#### Option 1: tracing-appender PR #2497 대기
- **GitHub**: https://github.com/tokio-rs/tracing/pull/2497
- **상태**: Open (2023년 3월부터 **2년 넘게 대기 중**)
- **내용**: Size-based rotation 기능 추가

**장점**:
- ✅ 공식 tokio/tracing 생태계
- ✅ 커뮤니티 지원 (6,355 stars)
- ✅ 장기 유지보수 보장

**치명적 단점**:
- ❌ **2년 동안 merge 안됨**
- ❌ Mergeable: False (conflict 있음)
- ❌ Author 코멘트: "**Not a priority for maintainers**"
- ❌ 언제 merge될지 **완전히 불명확**
- ❌ 19개 thumbs up 있지만 진행 없음

**결론**: ⛔ **기다리면 안됨** - Production 디스크 문제 리스크

> 근데 아직까지 로그 자동 제거 없다고 문제가 된 적은 없어보여서, 
> 그냥 냅두고 이거 머지되거나 할거 없으면 그 떄 들어가도 될 듯? 

---

#### Option 2: tracing-rolling-file (외부 crate)
- **GitHub**: https://github.com/cavivie/tracing-rolling-file
- **Stars**: 9 (매우 낮음)
- **최근 업데이트**: 2025-08-16 (3개월 전)
- **버전**: 0.1.3

**장점**:
- ✅ 시간 + 크기 rotation 모두 지원
- ✅ tracing 생태계 통합
- ✅ 최근 업데이트됨 (활발한 유지보수)
- ✅ rolling-file 기반 (검증된 로직)
- ✅ 즉시 사용 가능 (2-3시간 작업)

**단점**:
- ❌ **커뮤니티 매우 작음** (9 stars)
- ❌ **개인 개발자** 유지보수 (장기 지속성 불확실)
- ⚠️ 파일명 형식: Debian 스타일만 (iggy-server.log.1, .2)
  - 시간 정보(2025-11-25-14) 없음
- ⚠️ Rotation hook 없음 (cleanup 트리거 어려움)
- ❌ Apache 재단 프로젝트에 소규모 의존성 추가 적절한가?

**분석**:
- 코드가 단순 (692줄)하므로 fork 가능
- 하지만 요구사항(시간정보 + hook)에 맞추려면 수정 필요
- 수정하느니 차라리 vendoring이 나음

---

#### Option 3: rolling-file (원본)
- **GitHub**: https://github.com/Axcient/rolling-file-rs
- **Stars**: 16
- **최근 업데이트**: 2023-02-24 (**2년 전, dormant**)
- **기업**: Axcient (백업 회사)

**장점**:
- ✅ 기업 지원 (신뢰성)
- ✅ 더 나은 설계 (OsString, 버퍼 설정)
- ✅ 안정적 (2년간 변경 없음 = 버그 없음)

**치명적 단점**:
- ❌ **유지보수 중단** (2023년 이후 0 커밋)
- ❌ tracing 통합 수동 필요
- ❌ 향후 문제 발생 시 대응 불가

**결론**: ⛔ **비추천** - 죽은 프로젝트

---

#### Option 4: log4rs / flexi_logger
- **Stars**: 1,102 / 374 (많음!)
- **유지보수**: 매우 활발

**치명적 단점**:
- ❌ **`log` crate 생태계** (Iggy는 `tracing` 사용)
- ❌ 전체 로깅 시스템 변경 필요
- ❌ 대규모 리팩토링 필요

**결론**: ⛔ **불가능** - 생태계 불일치

---

### 의존성 비교표

| Crate | Stars | 최근 업데이트 | Time Rot. | Size Rot. | Tracing | 상태 | 추천도 |
|-------|-------|------------|-----------|-----------|---------|------|--------|
| **tracing-appender** | 6,355 | 2025-11 | ✅ | ❌ (PR 대기) | ✅ Native | Active | ⏰ 대기 불가 |
| **tracing-rolling-file** | 9 | 2025-08 | ✅ | ✅ | ✅ | Active | ⚠️ 수정 필요 |
| **rolling-file** | 16 | 2023-02 | ✅ | ✅ | ⚠️ Manual | Dormant | ❌ 중단됨 |
| **log4rs** | 1,102 | 2025-11 | ✅ | ✅ | ❌ log | Active | ❌ 생태계 |
| **flexi_logger** | 374 | 2025-11 | ✅ | ✅ | ❌ log | Active | ❌ 생태계 |
| **Custom (Vendoring)** | - | - | ✅ | ✅ | ✅ | - | ✅ **최적** |

---

### 왜 Vendoring을 선택했는가?

#### 1. **PR #2497 대기는 위험**
```
Timeline:
2023-03: PR 생성
2024년: 진행 없음
2025-03: 마지막 활동
현재: Merge 기미 없음

"Not a priority for maintainers" ← 명확한 신호
```
→ 언제까지 기다릴 수 없음

#### 2. **tracing-rolling-file은 불완전**
```rust
// 필요한 것:
iggy-server.log.2025-11-25-14      // ✅ 시간 정보
iggy-server.log.2025-11-25-14.1    // ✅ 크기 rotation
+ rotation hook                     // ✅ cleanup 트리거

// tracing-rolling-file 제공:
iggy-server.log.1                   // ❌ 시간 정보 없음
iggy-server.log.2                   // ✅ 크기 rotation
(no hook)                           // ❌ hook 없음
```
→ 어차피 수정해야 함 → 그럼 vendoring이 낫다

#### 3. **Apache 프로젝트 철학**
- 의존성 최소화
- 코드 통제
- 장기 안정성

→ 692줄 정도는 프로젝트에 포함해도 부담 없음

#### 4. **Iggy의 기존 패턴과 일치**
```rust
// Iggy는 이미 비슷한 패턴 사용:
- Segment rotation (크기 기반)
- Offset-based 파일명
- Periodic cleanup task
- IggyTimestamp utilities

→ 같은 패턴으로 구현하면 일관성 UP
```

---

### 최종 결정 근거

**Custom Implementation (Vendoring)을 선택한 이유:**

1. **즉시 해결** 가능 (6-7시간)
   - vs PR 대기 (언제까지?)
   - vs 외부 crate 수정 (비슷한 시간)

2. **요구사항 완벽 충족**
   - ✅ 시간 정보 포함 파일명
   - ✅ 크기 + 시간 rotation
   - ✅ Rotation hook
   - ✅ Retention cleanup

3. **장기 안정성**
   - ✅ Iggy 팀이 직접 관리
   - ✅ 버그 수정 즉시 가능
   - ✅ 성능 최적화 자유롭게

4. **Apache 프로젝트 적합**
   - ✅ 라이선스 호환 (MIT/Apache-2.0)
   - ✅ 의존성 최소화
   - ✅ 코드 복잡도 낮음 (692줄)

5. **리스크 낮음**
   - ✅ rolling-file 기반 (검증됨)
   - ✅ 코드가 단순함
   - ✅ 철저한 테스트 가능

---

## 참고 링크

- **tracing-appender PR #2497**: https://github.com/tokio-rs/tracing/pull/2497
- **tracing-rolling-file**: https://github.com/cavivie/tracing-rolling-file
- **rolling-file**: https://github.com/Axcient/rolling-file-rs
- **Iggy Segment 관리**: `core/server/src/streaming/segments/segment.rs`
- **Iggy Message Cleaner**: `core/server/src/shard/tasks/periodic/message_cleaner.rs` 
