import java.security.MessageDigest

plugins { `maven-publish` }

group = "dev.qperiapt"
version = "0.2.0-alpha.1"
layout.buildDirectory.set(file(providers.gradleProperty("qperiaptBuildDirectory").get()))

val candidate = providers.gradleProperty("qperiaptAar").map(::file)
val candidateSha256 = providers.gradleProperty("qperiaptAarSha256")
val sourcesJar = tasks.register<Jar>("sourcesJar") {
    archiveBaseName.set("q-periapt-android")
    archiveVersion.set(project.version.toString())
    archiveClassifier.set("sources")
    destinationDirectory.set(layout.buildDirectory.dir("libs"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    from("../src/main/java")
    from("../../../LICENSES/Apache-2.0.txt") { into("META-INF/licenses") }
    from("../../../LICENSES/MIT.txt") { into("META-INF/licenses") }
}

publishing {
    publications {
        create<MavenPublication>("sdk") {
            artifactId = "q-periapt-android"
            artifact(candidate) { extension = "aar" }
            artifact(sourcesJar)
            pom {
                packaging = "aar"
                name.set("Q-Periapt Android SDK")
                description.set("Owned signed-policy hybrid KEM runtime over native ABI 2 for Android API 23 and later")
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
        // Explicit local staging only. No upload endpoint or credentials.
        maven {
            name = "sdkStaging"
            url = file(providers.gradleProperty("qperiaptStagingRepository").get()).toURI()
        }
    }
}
tasks.withType<PublishToMavenRepository>().configureEach {
    doFirst {
        val pin = candidateSha256.get()
        check(pin.matches(Regex("[0-9a-f]{64}"))) { "AAR requires a pinned SHA-256" }
        val bytes = candidate.get().readBytes()
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        check(digest == pin) { "Selected AAR digest differs before staging" }
    }
}
