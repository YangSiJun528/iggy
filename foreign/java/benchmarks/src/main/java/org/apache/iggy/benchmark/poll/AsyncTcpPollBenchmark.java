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

package org.apache.iggy.benchmark.poll;

import org.apache.iggy.benchmark.util.BlockingAsyncClientAdapter;
import org.apache.iggy.client.async.tcp.AsyncIggyTcpClient;
import org.apache.iggy.client.blocking.IggyBaseClient;
import org.apache.iggy.message.PolledMessages;
import org.apache.iggy.message.PollingStrategy;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class AsyncTcpPollBenchmark extends BasePollBenchmark {

    @Param({"1", "4", "16"})
    public int concurrentRequests;

    private AsyncIggyTcpClient asyncClient;

    @Override
    protected void setupClient() throws Exception {
        asyncClient = new AsyncIggyTcpClient("localhost", iggyContainer.getTcpPort());
        asyncClient
                .connect()
                .thenCompose(v -> asyncClient.users().loginAsync("iggy", "iggy"))
                .get();
    }

    @Override
    protected void teardownClient() throws Exception {
        asyncClient.close().get();
    }

    @Override
    protected IggyBaseClient getManagementClient() {
        return new BlockingAsyncClientAdapter(asyncClient);
    }

    @Benchmark
    public List<PolledMessages> pollNext() {
        List<CompletableFuture<PolledMessages>> futures = new ArrayList<>(concurrentRequests);

        for (int i = 0; i < concurrentRequests; i++) {
            futures.add(asyncClient
                    .messages()
                    .pollMessagesAsync(
                            streamId,
                            topicId,
                            Optional.of(0L),
                            consumer,
                            PollingStrategy.next(),
                            messagesPerPoll,
                            false));
        }

        CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();

        List<PolledMessages> results = new ArrayList<>(concurrentRequests);
        for (CompletableFuture<PolledMessages> future : futures) {
            results.add(future.join());
        }

        return results;
    }

    @Benchmark
    public List<PolledMessages> pollOffset() {
        List<CompletableFuture<PolledMessages>> futures = new ArrayList<>(concurrentRequests);

        for (int i = 0; i < concurrentRequests; i++) {
            futures.add(asyncClient
                    .messages()
                    .pollMessagesAsync(
                            streamId,
                            topicId,
                            Optional.of(0L),
                            consumer,
                            PollingStrategy.offset(BigInteger.ZERO),
                            messagesPerPoll,
                            false));
        }

        CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();

        List<PolledMessages> results = new ArrayList<>(concurrentRequests);
        for (CompletableFuture<PolledMessages> future : futures) {
            results.add(future.join());
        }

        return results;
    }
}
