# Iggy Java SDK Benchmarks

JMH-based performance benchmarks for Iggy Java SDK.

## Purpose

These benchmarks measure **Java client implementation performance**, not server performance:
- Memory copy overhead in Java client
- Performance differences between `next` vs `offset` polling strategies
- Blocking vs Async client performance
- TCP vs HTTP protocol overhead

Server-side performance testing is done separately by the Iggy server project.

## Prerequisites

- JDK 17+
- Docker (Testcontainers manages the Iggy server automatically)

## Available Benchmarks

### Send Benchmarks
- **Single message**: `BlockingTcp/AsyncTcp/BlockingHttp SendSingleBenchmark`
  - Parameters: `payloadSizeBytes` (1KB, 10KB, 100KB, 1MB)
- **Batch messages**: `BlockingTcp/AsyncTcp/BlockingHttp SendBatchBenchmark`
  - Parameters: `messagesPerBatch` (10, 100, 1000), `payloadSizeBytes` (100B, 1KB)

### Poll Benchmarks
- **Poll messages**: `BlockingTcp/AsyncTcp/BlockingHttp PollBenchmark`
  - Methods: `pollNext`, `pollOffset`
  - Parameters: `messagesPerPoll` (1, 10, 100, 1000)

## Usage

```bash
# From repository root
cd foreign/java

# Run all benchmarks
./gradlew :iggy-benchmarks:jmh

# Run specific benchmark pattern
./gradlew :iggy-benchmarks:jmh -PjmhArgs='.*TcpPoll.*'

# Run with specific parameters
./gradlew :iggy-benchmarks:jmh -PjmhArgs='BlockingTcpPollBenchmark -p messagesPerPoll=1000'

# Quick test (no warmup, 1 iteration)
./gradlew :iggy-benchmarks:jmh -PjmhArgs='.*AsyncTcpPoll.* -wi 0 -i 1 -f 1'

# With GC profiling
./gradlew :iggy-benchmarks:jmh -PjmhArgs='.*TcpPoll.* -prof gc'
```

## Troubleshooting

**Container fails to start:** Make sure Docker is running.

**Verbose logging:** Edit `src/main/resources/logback.xml`:
```xml
<logger name="org.apache.iggy.benchmark" level="DEBUG"/>
```
