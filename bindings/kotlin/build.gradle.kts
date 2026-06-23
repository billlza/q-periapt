plugins {
    kotlin("jvm") version "2.0.0"
}

repositories { mavenCentral() }

dependencies {
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(22) // java.lang.foreign (FFM / Project Panama) is stable in JDK 22+
}

tasks.test {
    useJUnitPlatform()
    // The native lib must be on the library path: build it first with
    //   cargo build -p pqt-ffi --release
    systemProperty("java.library.path", "${rootDir}/../../target/release")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
