plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

dependencies {
    releaseImplementation(files("libs/aliang-core.aar"))
    debugImplementation(files(providers.gradleProperty("aliangDebugCore").getOrElse("libs/aliang-core.aar")))
    testImplementation("junit:junit:4.13.2")
}

android {
    namespace = "local.aliang.proxy"
    compileSdk = 36
    defaultConfig {
        applicationId = "local.aliang.proxy"
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.1.2"
        testInstrumentationRunner = "local.aliang.proxy.SafetyInstrumentation"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    val releasePassword = System.getenv("ANDROID_SIGNING_PASSWORD")
    if (!releasePassword.isNullOrBlank()) {
        signingConfigs {
            create("personalRelease") {
                storeFile = rootProject.file("../private/android-signing.p12")
                storePassword = releasePassword
                keyAlias = "aliang"
                keyPassword = releasePassword
            }
        }
        buildTypes.getByName("release").signingConfig = signingConfigs.getByName("personalRelease")
    }
}
