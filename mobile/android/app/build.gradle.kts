import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/** Builds crates/mobile-core for Android and generates its Kotlin bindings (scripts/build-core.sh). */
abstract class BuildCore : DefaultTask() {
    @get:Input abstract val profile: Property<String>
    @get:InputFile abstract val script: RegularFileProperty
    @get:OutputDirectory abstract val kotlinDir: DirectoryProperty
    @get:OutputDirectory abstract val jniLibsDir: DirectoryProperty
    @get:Inject abstract val exec: ExecOperations

    init {
        // Cargo decides what is stale; it is incremental and fast when nothing changed.
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun build() {
        exec.exec {
            commandLine(
                script.get().asFile.path,
                kotlinDir.get().asFile.path,
                jniLibsDir.get().asFile.path,
                profile.get(),
            )
        }
    }
}

/** The rustls-platform-verifier-android version in the workspace's Cargo.lock. */
abstract class RustlsVerifierVersion : ValueSource<String, RustlsVerifierVersion.Params> {
    interface Params : ValueSourceParameters {
        val lockFile: RegularFileProperty
    }

    override fun obtain(): String {
        val lines = parameters.lockFile.get().asFile.readLines()
        val at = lines.indexOfFirst { it.trim() == "name = \"rustls-platform-verifier-android\"" }
        return lines.drop(at + 1).firstOrNull { it.trimStart().startsWith("version = ") }
            ?.substringAfter('"')?.substringBefore('"')
            ?.takeIf { at >= 0 && it.isNotEmpty() }
            ?: error("rustls-platform-verifier-android not found in Cargo.lock")
    }
}

val rustlsVerifierVersion = providers.of(RustlsVerifierVersion::class.java) {
    parameters.lockFile.set(rootProject.layout.projectDirectory.file("../../Cargo.lock"))
}

configurations.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.rustls" && requested.name == "rustls-platform-verifier") {
            useVersion(rustlsVerifierVersion.get())
            because("the Kotlin half must match the Rust crate's version")
        }
    }
}

android {
    namespace = "pw.deadbolt.android"
    compileSdk = 37
    defaultConfig {
        applicationId = "pw.deadbolt.android"
        minSdk = 30 // setUserAuthenticationParameters; keep in step with scripts/build-core.sh
        targetSdk = 37
        versionCode = 1
        versionName = "0.0.0"
        ndk { abiFilters += "arm64-v8a" }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        // Vault's logging (Perf) reaches android.util.Log, a stub on the JVM.
        unitTests.isReturnDefaultValues = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar { it.uppercase() }
        val core = tasks.register<BuildCore>("buildDeadboltCore$name") {
            profile.set(if (variant.buildType == "release") "release" else "debug")
            script.set(rootProject.layout.projectDirectory.file("scripts/build-core.sh"))
            kotlinDir.set(layout.buildDirectory.dir("generated/deadbolt/${variant.name}/kotlin"))
            jniLibsDir.set(layout.buildDirectory.dir("generated/deadbolt/${variant.name}/jniLibs"))
        }
        variant.sources.kotlin?.addGeneratedSourceDirectory(core, BuildCore::kotlinDir)
        variant.sources.jniLibs?.addGeneratedSourceDirectory(core, BuildCore::jniLibsDir)
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.kotlinx.coroutines.android)
    implementation("${libs.jna.get()}@aar")
    implementation(libs.rustls.platform.verifier)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
