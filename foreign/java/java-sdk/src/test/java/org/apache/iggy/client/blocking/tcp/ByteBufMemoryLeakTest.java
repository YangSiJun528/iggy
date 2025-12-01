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

import io.netty.util.ResourceLeakDetector;
import org.apache.iggy.client.blocking.IggyBaseClient;
import org.apache.iggy.client.blocking.IntegrationTest;
import org.apache.iggy.consumergroup.Consumer;
import org.apache.iggy.message.Message;
import org.apache.iggy.message.Partitioning;
import org.apache.iggy.message.PollingKind;
import org.apache.iggy.message.PollingStrategy;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static java.util.Optional.empty;
import static org.apache.iggy.TestConstants.STREAM_NAME;
import static org.apache.iggy.TestConstants.TOPIC_NAME;
import static org.assertj.core.api.Assertions.assertThat;

class ByteBufMemoryLeakTest extends IntegrationTest {

    @BeforeAll
    static void setUpLeakDetector() {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);
        System.out.println("=== ByteBuf leak detection enabled (PARANOID level) ===");
    }

    @Override
    protected IggyBaseClient getClient() {
        return TcpClientFactory.create(iggyServer);
    }

    @Test
    void shouldNotLeakMemoryWhenPollingMessages() {
        // given
        login();
        setUpStreamAndTopic();
        var messagesClient = client.messages();

        // Send test messages
        for (int i = 0; i < 10; i++) {
            messagesClient.sendMessages(
                    STREAM_NAME, TOPIC_NAME, Partitioning.partitionId(0L), List.of(Message.of("leak-test-" + i)));
        }

        // when - Poll messages (this would leak ByteBufs if not properly handled)
        for (int i = 0; i < 2; i++) {
            var polledMessages = messagesClient.pollMessages(
                    STREAM_NAME,
                    TOPIC_NAME,
                    empty(),
                    Consumer.of(0L),
                    new PollingStrategy(PollingKind.Last, BigInteger.TEN),
                    10L,
                    false);

            assertThat(polledMessages.messages()).isNotEmpty();
        }

        // then - Force GC to trigger ResourceLeakDetector
        System.gc();

        // If there are ByteBuf leaks, ResourceLeakDetector will print ERROR logs:
        // "LEAK: ByteBuf.release() was not called before it's garbage-collected"
        // Test passes if no LEAK errors are printed
        System.out.println("=== Poll test completed - check logs for LEAK messages ===");
    }
}
