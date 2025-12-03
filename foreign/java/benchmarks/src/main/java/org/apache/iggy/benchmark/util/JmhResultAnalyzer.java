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

package org.apache.iggy.benchmark.util;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * Analyzes JMH benchmark results and calculates actual message throughput.
 *
 * <p>This tool parses JMH JSON output and calculates messages/sec by multiplying
 * operations/sec by the number of messages per operation (from benchmark parameters).
 */
public class JmhResultAnalyzer {

    private static final String SEPARATOR = "=".repeat(120);
    private static final String LINE = "-".repeat(120);

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: JmhResultAnalyzer <jmh-results.json>");
            System.exit(1);
        }

        String jsonFile = args[0];
        List<BenchmarkResult> results = parseResults(jsonFile);

        if (results.isEmpty()) {
            System.err.println("No benchmark results found in: " + jsonFile);
            System.exit(1);
        }

        // Sort by benchmark name
        results.sort(Comparator.comparing(r -> r.name));

        printResultsTable(results);
    }

    private static List<BenchmarkResult> parseResults(String jsonFile) {
        List<BenchmarkResult> results = new ArrayList<>();

        try (FileReader reader = new FileReader(jsonFile)) {
            Gson gson = new Gson();
            JsonArray benchmarks = gson.fromJson(reader, JsonArray.class);

            for (JsonElement element : benchmarks) {
                JsonObject benchmark = element.getAsJsonObject();
                BenchmarkResult result = analyzeBenchmark(benchmark);
                results.add(result);
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            System.exit(1);
        }

        return results;
    }

    private static BenchmarkResult analyzeBenchmark(JsonObject benchmark) {
        String benchmarkName = benchmark.get("benchmark").getAsString();
        JsonObject params = benchmark.getAsJsonObject("params");

        // Extract throughput (ops/sec)
        JsonObject primaryMetric = benchmark.getAsJsonObject("primaryMetric");
        double opsPerSec = primaryMetric.get("score").getAsDouble();
        double error = primaryMetric.get("scoreError").getAsDouble();

        // Determine multiplier based on benchmark type
        int multiplier = 1;
        StringBuilder paramInfo = new StringBuilder();

        // Check for batch/poll parameters
        Integer messagesPerBatch = getIntParam(params, "messagesPerBatch");
        Integer messagesPerPoll = getIntParam(params, "messagesPerPoll");
        Integer payloadSize = getIntParam(params, "payloadSizeBytes");

        if (messagesPerBatch != null) {
            multiplier = messagesPerBatch;
            paramInfo.append("batch=").append(messagesPerBatch);
        } else if (messagesPerPoll != null) {
            multiplier = messagesPerPoll;
            paramInfo.append("poll=").append(messagesPerPoll);
        } else {
            paramInfo.append("single");
        }

        if (payloadSize != null) {
            if (paramInfo.length() > 0) {
                paramInfo.append(", ");
            }
            paramInfo.append("size=").append(formatNumber(payloadSize)).append("B");
        }

        // Calculate messages/sec
        double messagesPerSec = opsPerSec * multiplier;
        double messagesError = error * multiplier;

        return new BenchmarkResult(
                benchmarkName,
                paramInfo.toString(),
                opsPerSec,
                error,
                messagesPerSec,
                messagesError,
                multiplier);
    }

    private static Integer getIntParam(JsonObject params, String key) {
        if (params == null || !params.has(key)) {
            return null;
        }
        try {
            return Integer.parseInt(params.get(key).getAsString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String formatNumber(double num) {
        if (num >= 1_000_000) {
            return String.format("%.2fM", num / 1_000_000);
        } else if (num >= 1_000) {
            return String.format("%.2fK", num / 1_000);
        } else {
            return String.format("%.2f", num);
        }
    }

    private static void printResultsTable(List<BenchmarkResult> results) {
        System.out.println();
        System.out.println(SEPARATOR);
        System.out.println("JMH Benchmark Results - Message Throughput Analysis");
        System.out.println(SEPARATOR);
        System.out.printf("%-50s %-20s %-15s %-15s %-10s%n",
                "Benchmark", "Parameters", "Ops/sec", "Messages/sec", "Multiplier");
        System.out.println(LINE);

        for (BenchmarkResult result : results) {
            String name = result.name;
            if (name.length() > 48) {
                name = "..." + name.substring(name.length() - 45);
            }

            String params = result.params;
            if (params.length() > 18) {
                params = params.substring(0, 15) + "...";
            }

            String ops = formatNumber(result.opsPerSec) + "/s";
            if (result.opsError > 0) {
                ops += " ±" + formatNumber(result.opsError);
            }

            String msgs = formatNumber(result.messagesPerSec) + "/s";
            if (result.messagesError > 0) {
                msgs += " ±" + formatNumber(result.messagesError);
            }

            String multiplier = "×" + result.multiplier;

            System.out.printf("%-50s %-20s %-15s %-15s %-10s%n",
                    name, params, ops, msgs, multiplier);
        }

        System.out.println(SEPARATOR);
        System.out.println();
        System.out.println("Note: Ops/sec × Multiplier = Messages/sec");
        System.out.println("      Multiplier is determined by messagesPerBatch or messagesPerPoll parameter");
        System.out.println();
    }

    private static class BenchmarkResult {
        final String name;
        final String params;
        final double opsPerSec;
        final double opsError;
        final double messagesPerSec;
        final double messagesError;
        final int multiplier;

        BenchmarkResult(String name, String params, double opsPerSec, double opsError,
                        double messagesPerSec, double messagesError, int multiplier) {
            this.name = name;
            this.params = params;
            this.opsPerSec = opsPerSec;
            this.opsError = opsError;
            this.messagesPerSec = messagesPerSec;
            this.messagesError = messagesError;
            this.multiplier = multiplier;
        }
    }
}
