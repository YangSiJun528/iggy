# Iggy Java SDK Benchmarks

JMH-based performance benchmarks for Iggy Java SDK.

## Benchmark Types

### Microbenchmarks
Pure client-side performance, no external dependencies:
- **MessageSerializationBenchmark** - Message encode/decode, BigInteger U64/U128 conversion ⭐

### Integration Benchmarks (`poll.*`, `send.*`)
End-to-end throughput with Iggy server:
- **Poll benchmarks** - Message polling performance
- **Send benchmarks** - Message sending performance
- Requires Docker (Testcontainers) or external server

## Quick Results

**Key findings from microbenchmarks:**

```
Message Serialization (results pending):
  Run './gradlew :iggy-benchmarks:jmh -PjmhArgs="MessageSerialization"' to benchmark
```

**Focus**: Measures the real performance bottleneck - message encode/decode with ArrayUtils.reverse() overhead.

## Prerequisites

- JDK 17+
- Docker (for integration benchmarks only)

## Usage

```bash
# From repository root
cd foreign/java

# Run all benchmarks
./gradlew :iggy-benchmarks:jmh

# Run microbenchmark (no Docker needed)
./gradlew :iggy-benchmarks:jmh -PjmhArgs="MessageSerialization"

# Quick test (fast iterations)
./gradlew :iggy-benchmarks:jmh -PjmhArgs="MessageSerialization -f 1 -wi 3 -i 5"

# With GC profiling (recommended to measure ByteBuf allocation overhead)
./gradlew :iggy-benchmarks:jmh -PjmhArgs="MessageSerialization -prof gc"

# Use external server (no Docker)
USE_EXTERNAL_SERVER=1 ./gradlew :iggy-benchmarks:jmh -PjmhArgs="poll"
```

## Troubleshooting

**Container fails to start:** Make sure Docker is running.

**Verbose logging:** Edit `src/main/resources/logback.xml`:
```xml
<logger name="org.apache.iggy.benchmark" level="DEBUG"/>
```
