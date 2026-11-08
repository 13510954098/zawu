plugins { kotlin("jvm") version "2.4.10" }
kotlin {
    jvmToolchain(21)
    sourceSets.main {
        kotlin.srcDir("../overlay/app/shared/app-data/src/commonMain/kotlin")
        kotlin.srcDir("../overlay/app/shared/app-data/src/jvmMain/kotlin")
    }
}
dependencies {
    implementation("io.ktor:ktor-http:3.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
tasks.test {
    useJUnitPlatform()
    systemProperty("lanerc.fixtures", file("../../../analysis/lanerc/dart-reference-fixtures.json").absolutePath)
    testLogging { events("passed", "skipped", "failed") }
}
