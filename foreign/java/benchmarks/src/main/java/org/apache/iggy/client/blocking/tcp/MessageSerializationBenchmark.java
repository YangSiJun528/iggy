/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.iggy.client.blocking.tcp;

import io.netty.buffer.ByteBuf;
import org.apache.iggy.message.Message;
import org.apache.iggy.message.MessageHeader;
import org.apache.iggy.message.MessageId;
import org.apache.iggy.message.Partitioning;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Benchmarks for message serialization/deserialization performance.
 * <p>
 * CRITICAL: This measures the real performance bottleneck in Iggy Java SDK.
 * Every message sent/received goes through BytesSerializer/Deserializer.
 * <p>
 * Key hot paths measured:
 * - Message encode/decode (runs for EVERY message)
 * - BigInteger U64 conversion with ArrayUtils.reverse() (9+ calls per message)
 * - ByteBuf allocation patterns
 * <p>
 * Expected findings:
 * - Larger payloads = slower serialization (linear)
 * - U64 conversion overhead = significant (ArrayUtils.reverse)
 * - GC pressure from ByteBuf allocations
 */
@State(Scope.Benchmark)
@Fork(value = 1)
@Warmup(iterations = 8, time = 1)
@Measurement(iterations = 10, time = 1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class MessageSerializationBenchmark {

    @Param({"small", "medium", "large"})
    private String payloadSize;

    private Message message;
    private MessageHeader header;
    private Partitioning partitioning;
    private BigInteger testBigInteger;

    @Setup(Level.Trial)
    public void setup() {
        // Create payload based on size parameter
        byte[] payload =
                switch (payloadSize) {
                    case "small" -> new byte[100]; // 100 bytes
                    case "medium" -> new byte[1024]; // 1 KB
                    case "large" -> new byte[10240]; // 10 KB
                    default -> throw new IllegalStateException("Invalid payloadSize: " + payloadSize);
                };

        // Fill with non-zero data to simulate real messages
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i % 256);
        }

        // Create a realistic message header
        header = new MessageHeader(
                BigInteger.valueOf(12345L), // checksum
                MessageId.from(BigInteger.valueOf(1L)), // id
                BigInteger.valueOf(100L), // offset
                BigInteger.valueOf(System.currentTimeMillis()), // timestamp
                BigInteger.valueOf(System.currentTimeMillis()), // originTimestamp
                0L, // userHeadersLength
                (long) payload.length // payloadLength
                );
        message = new Message(header, payload, Optional.empty());

        // Setup for partitioning benchmark
        partitioning = Partitioning.partitionId(123L);

        // Setup for U64 benchmark
        testBigInteger = BigInteger.valueOf(123456789L);
    }

    // ==================== Message Serialization ====================

    /**
     * Measures complete message serialization (header + payload).
     * This runs for EVERY message send operation.
     */
    @Benchmark
    public ByteBuf encodeMessage() {
        return BytesSerializer.toBytes(message);
    }

    /**
     * Measures message header serialization separately.
     * Header contains multiple BigInteger fields requiring U64/U128 conversion.
     */
    @Benchmark
    public ByteBuf encodeMessageHeader() {
        return BytesSerializer.toBytes(header);
    }

    // ==================== BigInteger U64 Conversion ====================

    /**
     * Measures toBytesAsU64() which calls ArrayUtils.reverse() - a major bottleneck.
     * This is called 9+ times per message (checksum, offset, timestamps, etc.)
     */
    @Benchmark
    public ByteBuf encodeBigIntegerU64() {
        return BytesSerializer.toBytesAsU64(testBigInteger);
    }

    // ==================== BigInteger U128 Conversion ====================

    /**
     * Measures toBytesAsU128() for message ID conversion.
     * Also uses ArrayUtils.reverse().
     */
    @Benchmark
    public ByteBuf encodeBigIntegerU128() {
        return BytesSerializer.toBytesAsU128(testBigInteger);
    }

    // ==================== Partitioning Serialization ====================

    /**
     * Measures partitioning strategy serialization.
     * partitionId() creates ByteBuffer and reverses bytes on every call.
     */
    @Benchmark
    public ByteBuf encodePartitioning() {
        return BytesSerializer.toBytes(partitioning);
    }
}
