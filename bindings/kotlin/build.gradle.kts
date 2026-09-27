import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.10"
    `maven-publish`
}

group = "dev.qperiapt"
version = "0.2.0-alpha.1"

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
        allWarningsAsErrors.set(true)
    }
}
tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
}
java { withSourcesJar() }

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
tasks.withType<Jar>().configureEach {
    from("../../LICENSES/Apache-2.0.txt") { into("META-INF/licenses") }
    from("../../LICENSES/MIT.txt") { into("META-INF/licenses") }
}
tasks.jar {
    manifest.attributes(
        "Automatic-Module-Name" to "dev.qperiapt.hybrid",
        "Implementation-Title" to "Q-Periapt Kotlin/JVM SDK",
        "Implementation-Version" to project.version,
        "QPeriapt-ABI" to "2",
        "QPeriapt-SDK-Extension" to "1",
    )
}

publishing {
    publications {
        create<MavenPublication>("sdk") {
            from(components["java"])
            pom {
                name.set("Q-Periapt Kotlin/JVM SDK")
                description.set("Owned signed-policy hybrid KEM runtime over native ABI 2; requires 64-bit JDK 25")
                url.set("https://github.com/billlza/q-periapt")
                licenses {
                    license { name.set("Apache License, Version 2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0.txt") }
                    license { name.set("MIT License"); url.set("https://opensource.org/license/mit") }
                }
                scm { url.set("https://github.com/billlza/q-periapt") }
            }
        }
    }
    repositories {
        // A local candidate repository only; no public registry or credentials.
        maven {
            name = "sdkStaging"
            val staging = providers.gradleProperty("qperiapt.stagingRepository")
                .map { file(it) }.getOrElse(layout.buildDirectory.dir("sdk-maven").get().asFile)
            url = staging.toURI()
        }
    }
}

tasks.test {
    useJUnitPlatform()
    // The native lib must be built first: cargo build -p q-periapt-ffi --release
    val libDir = file("${rootDir}/../../target/release")
    val lib = file("$libDir/${System.mapLibraryName("q_periapt_ffi_abi2")}")
    systemProperty("qperiapt.lib", providers.gradleProperty("qperiapt.lib").getOrElse(lib.absolutePath))
    systemProperty("java.library.path", libDir.absolutePath)
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}
