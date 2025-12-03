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

## Analyzing Results

To generate a detailed analysis report, run benchmarks with JSON output, then analyze:

```bash
# Step 1: Run benchmarks with JSON result output
./gradlew :iggy-benchmarks:jmh -PjmhArgs='.*TcpPoll.* -rf json -rff build/reports/jmh/results.json'

# Step 2: Analyze the results (after benchmarks complete)
./gradlew :iggy-benchmarks:jmhReport

# Or specify custom JSON file location
./gradlew :iggy-benchmarks:jmhReport -PjmhResultFile='path/to/custom-results.json'
```

**Note**: `jmhReport` runs independently and can analyze any JMH JSON results file.

The report calculates `messages/sec = ops/sec × multiplier` where:
- **Single message send**: multiplier = 1
- **Batch send**: multiplier = `messagesPerBatch`
- **Poll**: multiplier = `messagesPerPoll`

Example output:
```
========================================================================================================================
JMH Benchmark Results - Message Throughput Analysis
========================================================================================================================
Benchmark                                          Parameters           Ops/sec         Messages/sec    Multiplier
------------------------------------------------------------------------------------------------------------------------
...BlockingTcpPollBenchmark.pollNext              poll=1000            1.70K/s         1.70M/s         ×1000
...BlockingTcpSendBatchBenchmark.send             batch=100, size=1KB  2.50K/s         250.00K/s       ×100
========================================================================================================================

Note: Ops/sec × Multiplier = Messages/sec
      Multiplier is determined by messagesPerBatch or messagesPerPoll parameter
```

## Troubleshooting

**Container fails to start:** Make sure Docker is running.

**Verbose logging:** Edit `src/main/resources/logback.xml`:
```xml
<logger name="org.apache.iggy.benchmark" level="DEBUG"/>
```
