import groovy.json.JsonOutput
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

plugins { id("com.android.application") }

val exactAar = providers.gradleProperty("qperiaptAar").map(::file)
val smokeRoot = providers.gradleProperty("qperiaptSmokeRoot").map(::file)
val fixtureAssets = providers.gradleProperty("qperiaptFixtureAssets").map(::file)
val inputCapture = providers.gradleProperty("qperiaptInputCapture").map(::file)
val jvmCapture = providers.gradleProperty("qperiaptJvmCapture").map(::file)
val sdkMaven = providers.gradleProperty("qperiaptSdkMaven").map {
    check(it == "true") { "qperiaptSdkMaven must be absent or true" }
    true
}.getOrElse(false)
val sdkWorkload = providers.gradleProperty("qperiaptSdkWorkload").map {
    check(it == "true") { "qperiaptSdkWorkload must be absent or true" }
    true
}.getOrElse(sdkMaven)

android {
    namespace = "dev.qperiapt.androidsmoke"
    compileSdk = 35
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = "dev.qperiapt.androidsmoke"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "1"
    }
    buildTypes {
        getByName("release") {
            isDebuggable = false
            isMinifyEnabled = true
            vcsInfo.include = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
    flavorDimensions += "workload"
    productFlavors {
        create("full") { dimension = "workload" }
        create("minimal") { dimension = "workload" }
    }
    sourceSets {
        getByName("main").java.directories.add(smokeRoot.get().resolve("common").path)
        getByName("full").java.directories.add(smokeRoot.get().resolve(if (sdkWorkload) "sdk" else "full").path)
        getByName("full").assets.directories.add(fixtureAssets.get().path)
        getByName("minimal").java.directories.add(smokeRoot.get().resolve(if (sdkWorkload) "sdk-minimal" else "minimal").path)
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures { buildConfig = false }
    packaging {
        jniLibs {
            useLegacyPackaging = false
            // The AAR already contains stripped release binaries; retain their exact bytes.
            keepDebugSymbols += setOf("**/libq_periapt_ffi_abi2.so", "**/libqperiapt_jni_abi2.so")
        }
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    doFirst {
        check(!options.isFork) { "AGP release collector requires compilation in the selected JVM" }
        // Capture the actual task input collection, before compilation/R8. No test
        // source set or extra keep rule participates in either release variant.
        inputCapture.get().writeText(source.files.map { it.canonicalPath }.sorted().joinToString("\n", postfix = "\n"))
        // This is the JVM executing the actual compile task, not a separate Java probe.
        val identity = linkedMapOf(
            "schema" to 1,
            "kind" to "qperiapt.android_agp_build_jvm",
            "task" to path,
            "java_home" to File(System.getProperty("java.home")).canonicalPath,
            "java_version" to System.getProperty("java.version"),
            "java_runtime_version" to System.getProperty("java.runtime.version"),
            "java_vendor" to System.getProperty("java.vendor"),
            "java_vm_vendor" to System.getProperty("java.vm.vendor"),
            "java_vm_version" to System.getProperty("java.vm.version"),
            "compiler_java_home" to javaCompiler.get().metadata.installationPath.asFile.canonicalPath,
            "compiler_fork" to options.isFork,
        )
        Files.writeString(
            jvmCapture.get().toPath(),
            JsonOutput.toJson(identity) + "\n",
            StandardOpenOption.CREATE_NEW,
        )
    }
}

dependencies {
    if (sdkMaven) {
        check(!providers.gradleProperty("qperiaptAar").isPresent) { "Maven consumer cannot also select a file AAR" }
        implementation("dev.qperiapt:q-periapt-android:0.2.0")
    } else {
        implementation(files(exactAar))
    }
}

if (sdkMaven) {
    tasks.register("captureSdkResolution") {
        doLast {
            val variant = providers.gradleProperty("qperiaptVariant").get()
            check(variant in setOf("full", "minimal")) { "Unknown SDK consumer variant" }
            val artifacts = configurations.getByName("${variant}ReleaseRuntimeClasspath").resolvedConfiguration.resolvedArtifacts
            // AGP 9.4's built-in Kotlin adds stdlib even to this Java-only app.
            // Keep that observed tool dependency distinct from the AAR's empty POM dependency list.
            val expected = setOf("dev.qperiapt:q-periapt-android:0.2.0",
                "org.jetbrains.kotlin:kotlin-stdlib:2.2.10", "org.jetbrains:annotations:13.0")
            check(artifacts.map { it.moduleVersion.id.toString() }.toSet() == expected && artifacts.size == expected.size) {
                "Android SDK consumer runtime dependency closure differs"
            }
            val selected = artifacts.single { it.moduleVersion.id.group == "dev.qperiapt" }
            check(selected.moduleVersion.id.toString() == "dev.qperiapt:q-periapt-android:0.2.0")
            check(selected.extension == "aar")
            val digest = MessageDigest.getInstance("SHA-256").digest(selected.file.readBytes()).joinToString("") { "%02x".format(it) }
            val capture = file(providers.gradleProperty("qperiaptResolutionCapture").get())
            val runtime = artifacts.sortedBy { it.moduleVersion.id.toString() }.map {
                mapOf("coordinate" to it.moduleVersion.id.toString(), "path" to it.file.canonicalPath,
                    "sha256" to MessageDigest.getInstance("SHA-256").digest(it.file.readBytes()).joinToString("") { byte -> "%02x".format(byte) })
            }
            Files.writeString(capture.toPath(), JsonOutput.toJson(mapOf("coordinate" to selected.moduleVersion.id.toString(),
                "path" to selected.file.canonicalPath, "sha256" to digest, "runtime_dependencies" to runtime)) + "\n", StandardOpenOption.CREATE_NEW)
        }
    }
}
