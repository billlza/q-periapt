import java.security.MessageDigest
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins { kotlin("jvm") version "2.4.20" }

repositories {
    exclusiveContent {
        forRepository { maven { url = uri(providers.gradleProperty("sdkRepository").get()) } }
        filter { includeGroup("dev.qperiapt") }
    }
    mavenCentral()
}
dependencies { implementation("dev.qperiapt:q-periapt-hybrid:0.2.0") }
kotlin.compilerOptions {
    jvmTarget.set(JvmTarget.JVM_25)
    freeCompilerArgs.add("-Xjdk-release=25")
    allWarningsAsErrors.set(true)
}
tasks.withType<JavaCompile>().configureEach {
    options.release.set(25)
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}
tasks.register("recordRuntime") {
    doLast {
        val rows = configurations.runtimeClasspath.get().resolvedConfiguration.resolvedArtifacts
            .sortedBy { it.moduleVersion.id.toString() }.map {
                val sha = MessageDigest.getInstance("SHA-256").digest(it.file.readBytes())
                    .joinToString("") { byte -> "%02x".format(byte) }
                "${it.moduleVersion.id}\t${it.file.canonicalPath}\t$sha"
            }
        layout.buildDirectory.file("runtime.tsv").get().asFile.apply {
            parentFile.mkdirs()
            writeText(rows.joinToString("\n", postfix = "\n"))
        }
    }
}
tasks.register<JavaExec>("verifyInstalled") {
    dependsOn("classes", "recordRuntime")
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("consumer.ConsumerKt")
    systemProperty("qperiapt.lib", providers.gradleProperty("sdkLibrary").get())
    systemProperty("sdk.fixtures", file("fixtures").absolutePath)
    systemProperty("sdk.expectedJar", providers.gradleProperty("sdkJar").get())
    jvmArgs("--illegal-native-access=deny", "--enable-native-access=ALL-UNNAMED")
}
