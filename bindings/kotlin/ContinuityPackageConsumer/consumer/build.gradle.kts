import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.security.MessageDigest

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
tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}
application { mainClass.set("consumer.ContinuityClientKt") }
tasks.register("recordRuntime") {
    doLast {
        val rows = configurations.runtimeClasspath.get().resolvedConfiguration.resolvedArtifacts
            .sortedBy { it.moduleVersion.id.toString() }.map {
                val digest = MessageDigest.getInstance("SHA-256").digest(it.file.readBytes())
                    .joinToString("") { byte -> "%02x".format(byte) }
                "${it.moduleVersion.id}\t${it.file.canonicalPath}\t$digest"
            }
        layout.buildDirectory.file("runtime.tsv").get().asFile.apply {
            parentFile.mkdirs()
            writeText(rows.joinToString("\n", postfix = "\n"))
        }
    }
}
