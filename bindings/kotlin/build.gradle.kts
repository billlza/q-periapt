import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.10"
}

repositories { mavenCentral() }

dependencies {
    testImplementation(kotlin("test"))
}

// Build and test on JDK 25 LTS through the Gradle daemon JVM. Both Kotlin and
// Java use the stable JDK 25 API and bytecode; consumers require JDK 25 or newer.
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_25)
        freeCompilerArgs.add("-Xjdk-release=25")
    }
}
tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
}

tasks.test {
    useJUnitPlatform()
    // The native lib must be built first: cargo build -p q-periapt-ffi --release
    val libDir = file("${rootDir}/../../target/release")
    val lib = file("$libDir/${System.mapLibraryName("q_periapt_ffi_abi2")}")
    systemProperty("qperiapt.lib", lib.absolutePath)
    systemProperty("java.library.path", libDir.absolutePath)
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
