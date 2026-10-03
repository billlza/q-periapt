import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.20"
    `maven-publish`
}

group = "dev.qperiapt"
version = "0.0.0"
repositories { mavenCentral() }
dependencies { testImplementation(kotlin("test")) }
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_25)
        freeCompilerArgs.add("-Xjdk-release=25")
        allWarningsAsErrors.set(true)
    }
}
tasks.withType<JavaCompile>().configureEach { options.release.set(25) }
java { withSourcesJar() }
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
tasks.withType<Jar>().configureEach {
    from("../../../LICENSES/Apache-2.0.txt") { into("META-INF/licenses") }
    from("../../../LICENSES/MIT.txt") { into("META-INF/licenses") }
}
tasks.jar {
    manifest.attributes(
        "Automatic-Module-Name" to "dev.qperiapt.continuity",
        "Implementation-Title" to "Q-Periapt Continuity JVM candidate",
        "Implementation-Version" to project.version,
        "QPeriapt-Continuity-ABI" to "qpc-owner/1",
    )
}
publishing {
    publications { create<MavenPublication>("continuity") { from(components["java"]) } }
    repositories {
        maven {
            name = "candidate"
            url = layout.buildDirectory.dir("candidate-maven").get().asFile.toURI()
        }
    }
}
tasks.test {
    useJUnitPlatform()
    val library = providers.gradleProperty("qperiapt.continuity.lib")
    doFirst { require(library.isPresent) { "select the actual installed qpc-owner/1 library" } }
    systemProperty("qperiapt.continuity.lib", library.getOrElse(""))
    jvmArgs("--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny")
}
