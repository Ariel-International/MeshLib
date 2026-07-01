plugins {
    id("com.android.application") version "8.2.2"
}

android {
    namespace = "com.mesh.test"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.mesh.test"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    buildTypes {
        debug {
            isDebuggable = true
        }
    }
}

dependencies {
    // The jar under test — same artifact the wallet ships
    implementation(fileTree(mapOf("dir" to "../build/libs", "include" to listOf("meshlib.jar"))))
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
}
