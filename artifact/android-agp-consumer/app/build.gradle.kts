import groovy.json.JsonOutput
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption

plugins { id("com.android.application") }

val exactAar = providers.gradleProperty("qperiaptAar").map(::file)
val smokeRoot = providers.gradleProperty("qperiaptSmokeRoot").map(::file)
val fixtureAssets = providers.gradleProperty("qperiaptFixtureAssets").map(::file)
val inputCapture = providers.gradleProperty("qperiaptInputCapture").map(::file)
val jvmCapture = providers.gradleProperty("qperiaptJvmCapture").map(::file)

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
        getByName("full").java.directories.add(smokeRoot.get().resolve("full").path)
        getByName("full").assets.directories.add(fixtureAssets.get().path)
        getByName("minimal").java.directories.add(smokeRoot.get().resolve("minimal").path)
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

dependencies { implementation(files(exactAar)) }
