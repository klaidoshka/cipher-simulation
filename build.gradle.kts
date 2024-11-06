plugins {
    id("java")
}

group = "com.github.klaidoshka"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-ext-jdk18on:1.78.1")
}