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

plugins {
    id("iggy.java-common-conventions")
    alias(libs.plugins.shadow)
}

dependencies {
    implementation(project(":iggy"))
    implementation(libs.jmh.core)
    implementation(libs.slf4j.api)
    implementation(libs.testcontainers)
    implementation("com.google.code.gson:gson:2.10.1")
    annotationProcessor(libs.jmh.generator)
    runtimeOnly(libs.logback.classic)
    runtimeOnly(libs.netty.dns.macos) { artifact { classifier = "osx-aarch_64" } }
}

tasks.shadowJar {
    archiveBaseName.set("iggy-jmh-benchmarks")
    archiveClassifier.set("")

    manifest {
        attributes["Main-Class"] = "org.openjdk.jmh.Main"
    }

    mergeServiceFiles()
}

tasks.register<JavaExec>("jmh") {
    group = "benchmark"
    description = "Run JMH benchmarks. Use -PjmhArgs to pass JMH arguments."

    dependsOn(tasks.shadowJar)

    val jmhArgs = project.findProperty("jmhArgs")?.toString() ?: ""
    val jarFile = tasks.shadowJar.get().archiveFile.get().asFile

    // Ensure build/reports/jmh directory exists
    doFirst {
        file("build/reports/jmh").mkdirs()
    }

    classpath = files(jarFile)
    mainClass.set("org.openjdk.jmh.Main")
    args = jmhArgs.split(" ").filter { it.isNotBlank() }

    // Disable Gradle caching to ensure benchmarks always run
    outputs.upToDateWhen { false }
}

tasks.register<JavaExec>("jmhReport") {
    group = "benchmark"
    description = "Analyze JMH benchmark results and generate report. Use -PjmhResultFile to specify JSON file path."

    dependsOn(tasks.shadowJar)

    val resultFilePath = project.findProperty("jmhResultFile")?.toString()
        ?: "build/reports/jmh/results.json"
    val resultsFile = file(resultFilePath)

    // Only run if results file exists
    onlyIf {
        if (!resultsFile.exists()) {
            logger.warn("JMH results file not found: ${resultsFile.absolutePath}")
            logger.warn("Run benchmarks with: ./gradlew :iggy-benchmarks:jmh -PjmhArgs='-rf json -rff ${resultFilePath}'")
            false
        } else {
            true
        }
    }

    val jarFile = tasks.shadowJar.get().archiveFile.get().asFile

    classpath = files(jarFile)
    mainClass.set("org.apache.iggy.benchmark.util.JmhResultAnalyzer")
    args = listOf(resultsFile.absolutePath)
}
