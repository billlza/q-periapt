import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.4.20"
    application
}
repositories {
    exclusiveContent {
        forRepository {
            maven { url = uri(providers.gradleProperty("qperiapt.repository").get()) }
        }
        filter { includeModule("dev.qperiapt", "q-periapt-continuity-kotlin") }
    }
    mavenCentral()
}
dependencies { implementation("dev.qperiapt:q-periapt-continuity-kotlin:0.0.0") }
kotlin.compilerOptions {
    jvmTarget.set(JvmTarget.JVM_25)
    freeCompilerArgs.add("-Xjdk-release=25")
    allWarningsAsErrors.set(true)
}
tasks.withType<JavaCompile>().configureEach { options.release.set(25) }
application { mainClass.set("consumer.ContinuityClientKt") }
