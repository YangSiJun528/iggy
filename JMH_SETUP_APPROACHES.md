# JMH Setup Approaches for Java Benchmarks

This document compares two common approaches for setting up JMH (Java Microbenchmark Harness) in Gradle projects. This is a general reference document, not specific to any particular project.

---

## Approach 1: Shadow Jar

### Overview
Uses the Shadow plugin to create an executable uber-jar containing all dependencies and JMH infrastructure.

### Configuration

```kotlin
plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

dependencies {
    implementation("org.openjdk.jmh:jmh-core:1.37")
    annotationProcessor("org.openjdk.jmh:jmh-generator-annprocess:1.37")
}

tasks.shadowJar {
    archiveClassifier.set("benchmarks")
    manifest {
        attributes["Main-Class"] = "org.openjdk.jmh.Main"
    }
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
}

tasks.register<JavaExec>("jmh") {
    dependsOn(tasks.shadowJar)
    classpath = files(tasks.shadowJar.get().archiveFile)
    mainClass.set("org.openjdk.jmh.Main")
}
```

### Execution

```bash
# Build
./gradlew :benchmarks:shadowJar

# Run all benchmarks
java -jar benchmarks/build/libs/project-benchmarks.jar

# Run specific benchmark
java -jar benchmarks/build/libs/project-benchmarks.jar ".*MessageSend.*"

# With JMH options
java -jar benchmarks/build/libs/project-benchmarks.jar -wi 3 -i 5 -f 1

# Or via Gradle task
./gradlew :benchmarks:jmh
```

### Pros
- **Simple configuration**: Minimal Gradle setup required
- **Portable**: Single executable JAR can be distributed and run anywhere
- **Explicit control**: Full control over JMH execution via command-line arguments
- **Apache standard**: Used by Apache Kafka and other major projects
- **IDE-friendly**: Easy to debug by running the JAR with specific arguments
- **No special Gradle knowledge needed**: Standard Java execution

### Cons
- **Manual argument passing**: Must specify JMH options as command-line arguments
- **Less Gradle integration**: Can't leverage Gradle's task configuration as extensively
- **Larger JAR size**: Includes all dependencies (though usually not a concern)

### Use Cases
- When you want maximum portability and distribution
- When developers prefer command-line control
- When following Apache project conventions
- When simplicity is preferred over advanced Gradle features

---

## Approach 2: JMH Gradle Plugin (Community-Supported)

### Overview
Uses the community-supported JMH Gradle plugin (`me.champeau.jmh`) for native Gradle integration. Note that this is not an official JMH plugin, but is widely used in the community.

### Configuration

```kotlin
plugins {
    id("java")
    id("me.champeau.jmh") version "0.7.2"
}

dependencies {
    // JMH dependencies are managed by the plugin
}

jmh {
    jmhVersion = "1.37"

    // Benchmark selection
    val jmhIncludes = findProperty("jmh.includes")
    if (jmhIncludes != null) {
        includes = jmhIncludes.toString().split(",")
    }

    // Fork configuration
    fork = (findProperty("jmh.fork") as? String)?.toInt() ?: 1

    // Iterations
    iterations = (findProperty("jmh.iterations") as? String)?.toInt() ?: 5
    warmupIterations = (findProperty("jmh.warmupIterations") as? String)?.toInt() ?: 5

    // Profilers
    val jmhProfilers = findProperty("jmh.profilers")
    if (jmhProfilers != null) {
        profilers = jmhProfilers.toString().split(",")
    }

    // Threads
    threads = (findProperty("jmh.threads") as? String)?.toInt() ?: 1

    // Verbosity
    if (findProperty("jmh.verbose") != null) {
        verbosity = "EXTRA"
    }

    // JVM args
    val jmhJvmargs = findProperty("jmh.jvmargs")
    if (jmhJvmargs != null) {
        jvmArgsAppend = jmhJvmargs.toString().split(" ")
    }

    // Force GC
    forceGC = (findProperty("jmh.forceGC") as? String)?.toBoolean() ?: true

    // Benchmark parameters
    val jmhParams = findProperty("jmh.params")
    if (jmhParams != null) {
        val parameters = mutableMapOf<String, List<String>>()
        jmhParams.toString().split(";").forEach {
            val parts = it.split("=")
            parameters[parts[0]] = parts[1].split(",")
        }
        benchmarkParameters = parameters
    }

    duplicateClassesStrategy = DuplicatesStrategy.EXCLUDE
}

// Disable output caching to ensure benchmarks run every time
tasks.jmh {
    outputs.upToDateWhen { false }
}
```

### Execution

```bash
# Run all benchmarks
./gradlew jmh

# Run specific benchmarks
./gradlew jmh -Pjmh.includes=".*MessageSend.*"

# Configure iterations
./gradlew jmh -Pjmh.iterations=10 -Pjmh.warmupIterations=5

# Enable profilers
./gradlew jmh -Pjmh.profilers="gc,stack"

# Multiple threads
./gradlew jmh -Pjmh.threads=4

# Custom JVM args
./gradlew jmh -Pjmh.jvmargs="-Xmx4g -XX:+UseG1GC"

# Benchmark parameters (message size, batch size, etc.)
./gradlew jmh -Pjmh.params="messageSize=1024,10240;batchSize=10,100"

# Verbose output
./gradlew jmh -Pjmh.verbose
```

### Pros
- **Native Gradle integration**: First-class Gradle task with full configuration
- **Project properties**: Control benchmarks via `-P` flags without rebuilding
- **Advanced features**: Easy profiler integration, parameter sweeps
- **CI/CD friendly**: Easier to script and parameterize in build systems
- **Automatic caching control**: Can disable task caching for benchmarks
- **Type-safe configuration**: Gradle DSL with IDE support

### Cons
- **More complex setup**: Requires understanding Gradle plugin configuration
- **Less portable**: Must run via Gradle (can't distribute standalone JAR easily)
- **Gradle dependency**: Requires Gradle installation to run benchmarks
- **Learning curve**: Developers need to learn plugin-specific options

### Use Cases
- When you want maximum Gradle integration
- When benchmarks are primarily run in CI/CD
- When you need sophisticated parameter sweeps
- When you want to control benchmarks via project properties

---

## Real-World Examples

### Apache Kafka (Shadow Jar)

```kotlin
project(':jmh-benchmarks') {
    apply plugin: 'com.gradleup.shadow'

    shadowJar {
        archiveBaseName = 'kafka-jmh-benchmarks'
    }

    dependencies {
        implementation libs.jmhCore
                annotationProcessor libs.jmhGeneratorAnnProcess
    }

    jar {
        manifest {
            attributes "Main-Class": "org.openjdk.jmh.Main"
        }
    }

    task jmh(type: JavaExec, dependsOn: [':jmh-benchmarks:clean', ':jmh-benchmarks:shadowJar']) {
    mainClass = "-jar"
    doFirst {
        if (System.getProperty("jmhArgs")) {
            args System.getProperty("jmhArgs").split(' ')
        }
        args = [shadowJar.archiveFile.get().asFile, *args]
    }
}
}
```

**Usage:**
```bash
./gradlew :jmh-benchmarks:jmh -DjmhArgs="-wi 3 -i 5"
```

### Example Project Using JMH Plugin

```kotlin
plugins {
    id("me.champeau.jmh") version "0.7.2"
}

jmh {
    jmhVersion = "1.37"
    includes = listOf(".*Benchmark.*")
    fork = 2
    warmupIterations = 3
    iterations = 5
}
```

**Usage:**
```bash
./gradlew jmh -Pjmh.profilers=gc
```

---

## Comparison Summary

| Aspect | Shadow Jar | JMH Gradle Plugin |
|--------|------------|-------------------|
| **Setup Complexity** | Simple | Moderate |
| **Portability** | High (standalone JAR) | Low (requires Gradle) |
| **Gradle Integration** | Basic | Native |
| **Configuration** | Command-line args | Project properties |
| **CI/CD Friendly** | Good | Excellent |
| **Apache Projects** | Kafka, others | Less common |
| **Community Support** | Official JMH | Community plugin |
| **Learning Curve** | Low | Moderate |

---

## Choosing the Right Approach

### Use Shadow Jar when:
- You want maximum portability and distribution
- You prefer simplicity over advanced features
- You're following Apache project conventions
- Your team is more comfortable with command-line tools
- You don't need frequent parameter changes

### Use JMH Plugin when:
- You need sophisticated parameter sweeps in CI/CD
- You prefer Gradle-centric workflows
- You want to change benchmark parameters without rebuilding
- You need advanced profiler integration out of the box
- Your team is already heavily invested in Gradle

---

## Migration Path

If switching from Shadow Jar to JMH Plugin (or vice versa):

**Shadow Jar → JMH Plugin:**
1. Add `me.champeau.jmh` plugin
2. Remove shadow plugin configuration
3. Move benchmark parameters to `jmh {}` block
4. Update CI/CD scripts to use `-P` properties
5. Update documentation

**JMH Plugin → Shadow Jar:**
1. Add shadow plugin
2. Configure shadowJar task
3. Remove `jmh {}` configuration block
4. Update CI/CD to use JAR arguments
5. Update documentation

The benchmark code itself (JMH annotations, `@Benchmark`, etc.) remains unchanged in either case.

---

## Conclusion

Both approaches are valid and widely used in production. The Shadow Jar approach is simpler, more portable, and aligns with Apache project conventions (used by Kafka). The JMH Gradle Plugin offers better Gradle integration but adds complexity and reduces portability.

Choose based on your project's specific needs, team preferences, and existing infrastructure.
