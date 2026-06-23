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
    // The native lib must be built first: cargo build -p pqt-ffi --release
    val libDir = file("${rootDir}/../../target/release")
    val lib = file("$libDir/${System.mapLibraryName("pqt_ffi")}")
    systemProperty("pqt.lib", lib.absolutePath)
    systemProperty("java.library.path", libDir.absolutePath)
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
