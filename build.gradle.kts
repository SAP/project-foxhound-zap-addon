import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.13.1"
    id("com.diffplug.spotless")
    id("org.zaproxy.common")
}

description = "Capture and analysis of client-side data flows from the Foxhound browser."

zapAddOn {
    addOnId.set("foxhound")
    addOnName.set("Foxhound ZAP Add-on")
    zapVersion.set("2.17.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    releaseLink.set("https://github.com/SAP/project-foxhound-zap-addon/compare/v@PREVIOUS_VERSION@...v@CURRENT_VERSION@")
    unreleasedLink.set("https://github.com/SAP/project-foxhound-zap-addon/compare/v@CURRENT_VERSION@...HEAD")

    manifest {
        author.set("Thomas Barber")
        url.set("https://github.com/SAP/project-foxhound-zap-addon")
        repo.set("https://github.com/SAP/project-foxhound-zap-addon")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        // Don't search the add-on classes to prevent the inclusion
        // of the scanner, it's added/removed by the extension.
        classpath.setFrom(files())
        extensions {
            register("org.zaproxy.zap.extension.foxhound.ExtensionFoxhound")
        }
        dependencies {
            addOns {
                register("selenium") {
                    version.set(">=15.44.0")
                }
                register("network") {
                    version.set(">=0.1.0")
                }
                register("commonlib") {
                    version.set(">= 1.40.0 & < 2.0.0")
                }
                register("pscan") {
                    version.set(">= 0.2.0 & < 1.0.0")
                }
            }
        }
        pscanrules {
            register("org.zaproxy.zap.extension.foxhound.FoxhoundExportServer")
        }
    }
}

java {
    val javaVersion = JavaVersion.VERSION_17
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

repositories {
    mavenCentral()
    // Needed for the ZAP snapshot dependencies
    maven {
        url = uri("https://central.sonatype.com/repository/maven-snapshots/")
    }
}

spotless {
    kotlinGradle {
        ktlint()
    }
    java {
        clearSteps()
        googleJavaFormat("1.17.0").aosp()
    }
}

dependencies {
    compileOnly("org.zaproxy:zap:2.17.0")
    compileOnly("org.zaproxy.addon:commonlib:1.40.0")
    compileOnly("org.zaproxy.addon:network:0.1.0")
    // Snapshot version includes support for custom browsers
    compileOnly("org.zaproxy.addon:selenium:15.49.0")
    compileOnly("org.zaproxy.addon:pscan:0.2.0")
    testImplementation(platform("org.junit:junit-bom:6.0.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("io.github.bonigarcia:webdrivermanager:6.3.3")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
