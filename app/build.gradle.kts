import java.security.MessageDigest
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

val namuKeystoreFile = rootProject.file("keystore/namu.jks")
val namuKeystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}



// 打包前校验内核产物与源码一致：版本号 + Rust 源码哈希 + Cargo 清单/锁文件哈希 +
// 两个 .so 自身摘要。全部按内容比对，不依赖 mtime（zip 解压会重置时间），
// 也能发现「源码没变但二进制被替换」的误打包。
val verifyKernel = tasks.register("verifyKernel") {
    val coreSrc = rootProject.file("core/src")
    val libRs = rootProject.file("core/src/lib.rs")
    val jni = file("src/main/jniLibs")
    doLast {
        val expected = Regex("to_jstring\\(&mut env, \"([0-9]+\\.[0-9]+\\.[0-9]+)\"")
            .find(libRs.readText())?.groupValues?.get(1)
            ?: throw GradleException("无法从 core/src/lib.rs 读取内核版本号")
        // 用源码内容哈希而不是 mtime：zip 解压、git 检出都会把 .so 和 .rs 的时间重置，
        // 只比时间会让「没改代码的人也打不了包」。哈希只随源码内容变化。
        val digest = MessageDigest.getInstance("SHA-256")
        coreSrc.walkTopDown()
            .filter { it.isFile && it.extension == "rs" }
            .sortedBy { it.relativeTo(coreSrc).path }
            .forEach { digest.update(it.readBytes()) }
        val expectedHash = digest.digest().joinToString("") { b -> "%02x".format(b) }
        val cargoDigest = MessageDigest.getInstance("SHA-256")
        val coreDir = rootProject.file("core")
        listOf(".cargo/config.toml", "Cargo.lock", "Cargo.toml")
            .map { coreDir.resolve(it) }
            .filter { it.isFile }
            .sortedBy { it.relativeTo(coreDir).path }
            .forEach {
                cargoDigest.update((it.relativeTo(coreDir).path + "\n").toByteArray())
                cargoDigest.update(it.readBytes())
            }
        val expectedCargoHash = cargoDigest.digest().joinToString("") { b -> "%02x".format(b) }
        fun sha256(file: java.io.File): String {
            val d = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { ins ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    d.update(buf, 0, n)
                }
            }
            return d.digest().joinToString("") { b -> "%02x".format(b) }
        }
        val stamp = jni.resolve("kernel_version.txt")
        val lines = if (stamp.exists()) stamp.readText().trim().lines() else emptyList()
        val actualVer = lines.getOrNull(0).orEmpty()
        val actualSrcHash = lines.getOrNull(1).orEmpty()
        val actualCargoHash = lines.getOrNull(2).orEmpty()
        if (actualVer != expected) {
            throw GradleException("内核产物版本($actualVer)与源码($expected)不一致，请先运行 core/build-android.sh")
        }
        if (actualSrcHash != expectedHash) {
            throw GradleException("内核产物与 Rust 源码内容不一致（.so 是旧的），请运行 core/build-android.sh")
        }
        if (actualCargoHash != expectedCargoHash) {
            throw GradleException("Cargo 清单/锁文件已变化，请重新运行 core/build-android.sh")
        }
        listOf("arm64-v8a", "armeabi-v7a").forEachIndexed { index, abi ->
            val so = jni.resolve("$abi/libnanmen_core.so")
            if (!so.exists()) throw GradleException("缺少 $abi/libnanmen_core.so")
            val actualSo = lines.getOrNull(3 + index).orEmpty()
            if (sha256(so) != actualSo) {
                throw GradleException("$abi/libnanmen_core.so 与构建记录不一致（二进制被替换？），请重新编译内核")
            }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyKernel) }

android {
    namespace = "com.namu.dns"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.namu.dns"
        minSdk = 31
        targetSdk = 36
        versionCode = 152
        versionName = "3.6.2"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    signingConfigs {
        create("release") {
            if (namuKeystoreFile.exists()) {
                storeFile = namuKeystoreFile
                storePassword = namuKeystoreProps.getProperty("storePassword", "")
                keyAlias = namuKeystoreProps.getProperty("keyAlias", "namu")
                keyPassword = namuKeystoreProps.getProperty("keyPassword", "")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (namuKeystoreFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            if (namuKeystoreFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        dex {
            // minSdk 31 默认把 dex 以未压缩方式打包，APK 会接近翻倍；
            // 这里保留传统压缩，native 库仍不压缩以支持直接 mmap。
            useLegacyPackaging = true
        }
        jniLibs {
            useLegacyPackaging = false
        }
    }

    lint {
        // 依赖版本由当前 Compose BOM/编译组合锁定，升级需单独回归；ChromeOS x86_64 不在双 ABI 交付范围。
        disable += setOf("GradleDependency", "ChromeOsAbiSupport", "ObsoleteSdkInt")
        warningsAsErrors = true
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("androidx.camera:camera-camera2:1.5.0")
    implementation("androidx.camera:camera-lifecycle:1.5.0")
    implementation("androidx.camera:camera-view:1.5.0")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
    // Android 的 org.json 在 JVM 单测里是空壳；显式引入真实实现，配置序列化测试才能跑。
    testImplementation("org.json:json:20240303")
    testImplementation("androidx.test.ext:junit:1.2.1")
    testImplementation("androidx.test:core-ktx:1.6.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("app.cash.turbine:turbine:1.2.0")
    androidTestImplementation(platform("androidx.compose:compose-bom:2024.12.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
