plugins {
    kotlin("jvm") version "2.1.0"
}

group = "com.headerfusion"
version = "2.1"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2023.12.1")
    implementation("com.google.code.gson:gson:2.10.1")
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
}
