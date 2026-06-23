// Auto-provision the JDK 22 toolchain (stable java.lang.foreign) so the build is
// self-contained — no manual JDK install required.
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

rootProject.name = "pqt-hybrid"
