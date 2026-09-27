pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        val candidate = providers.gradleProperty("qperiaptMavenRepository")
        if (candidate.isPresent) {
            exclusiveContent {
                forRepository { maven { url = file(candidate.get()).toURI() } }
                filter { includeGroup("dev.qperiapt") }
            }
        }
        google()
        mavenCentral()
    }
}
rootProject.name = "qperiapt-agp-consumer"
include(":app")
