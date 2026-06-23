import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.20"
}

repositories { mavenCentral() }

dependencies {
    testImplementation(kotlin("test"))
}

// Requires a JDK >= 22 (stable java.lang.foreign / FFM); compiles/runs on the
// Gradle daemon JVM (set JAVA_HOME). Bytecode target pinned to 22 (FFM's floor)
// with Java aligned, so it runs on any JDK >= 22 (CI uses 22; dev here uses 26).
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_22)
    }
}
tasks.withType<JavaCompile>().configureEach {
    options.release.set(22)
}

tasks.test {
    useJUnitPlatform()
    // The native lib must be built first: cargo build -p pqt-ffi --release
    val libDir = file("${rootDir}/../../target/release")
    val lib = file("$libDir/${System.mapLibraryName("pqt_ffi")}")
    systemProperty("pqt.lib", lib.absolutePath)
    systemProperty("java.library.path", libDir.absolutePath)
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
