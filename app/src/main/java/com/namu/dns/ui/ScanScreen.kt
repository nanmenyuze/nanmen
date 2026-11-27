package com.namu.dns.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CameraAlt
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.namu.dns.Actions
import com.namu.dns.core.LocalAppContainer
import kotlinx.coroutines.launch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * CameraX 预览 + MLKit 二维码识别。识别到内容后走现有的导入/订阅流程；
 * 拒绝相机权限或相机不可用时，切换到手动粘贴，保证不阻断导入。
 */
@androidx.annotation.OptIn(ExperimentalGetImage::class)
@Composable
fun ScanScreen(onDone: () -> Unit) {
    val context = LocalContext.current
    val container = LocalAppContainer.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var manual by remember { mutableStateOf(false) }
    var importing by remember { mutableStateOf(false) }
    var manualText by remember { mutableStateOf("") }
    var cameraError by remember { mutableStateOf<String?>(null) }
    var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    var analysis by remember { mutableStateOf<ImageAnalysis?>(null) }
    var scanner by remember { mutableStateOf<com.google.mlkit.vision.barcode.BarcodeScanner?>(null) }
    val handled = remember { AtomicBoolean(false) }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { ok ->
        granted = ok
        manual = !ok
    }

    LaunchedEffect(Unit) {
        if (!granted) permissionLauncher.launch(Manifest.permission.CAMERA)
    }
    LaunchedEffect(manual) {
        // 切到手动输入后停止识别，避免相机还在后台重复触发导入。
        if (manual) analysis?.clearAnalyzer()
    }

    DisposableEffect(Unit) {
        onDispose {
            analysis?.clearAnalyzer()
            scanner?.close()
            cameraProvider?.unbindAll()
            analysisExecutor.shutdown()
        }
    }

    fun importRaw(raw: String) {
        if (raw.isBlank() || importing) return
        scope.launch {
            importing = true
            try {
                val result = Actions.importSubscription(raw.trim(), append = true)
                if (result.nodes > 0) {
                    container.messages.show("已导入 ${result.nodes} 个节点")
                    onDone()
                } else {
                    container.messages.show(Actions.subscriptionRefreshMessage(result))
                    handled.set(false)
                }
            } catch (e: Exception) {
                container.messages.show(e.message ?: "二维码内容不是可用的节点或订阅")
                handled.set(false)
            } finally {
                importing = false
            }
        }
    }

    Box(Modifier.fillMaxSize().background(NamuColors.Bg)) {
        if (!manual && granted) {
            AndroidView(
                factory = { ctx ->
                    val previewView = PreviewView(ctx).apply {
                        scaleType = PreviewView.ScaleType.FILL_CENTER
                        implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                    }
                    val future = ProcessCameraProvider.getInstance(ctx)
                    future.addListener({
                        runCatching {
                            val provider = future.get()
                            cameraProvider = provider
                            val preview = Preview.Builder().build().also {
                                it.setSurfaceProvider(previewView.surfaceProvider)
                            }
                            val imageAnalysis = ImageAnalysis.Builder()
                                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                .build()
                            analysis = imageAnalysis
                            val codeScanner = BarcodeScanning.getClient(
                                BarcodeScannerOptions.Builder()
                                    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                                    .build(),
                            )
                            scanner = codeScanner
                            imageAnalysis.setAnalyzer(analysisExecutor) { imageProxy: ImageProxy ->
                                if (handled.get()) {
                                    imageProxy.close()
                                    return@setAnalyzer
                                }
                                val media = imageProxy.image
                                if (media == null) {
                                    imageProxy.close()
                                    return@setAnalyzer
                                }
                                val image = InputImage.fromMediaImage(media, imageProxy.imageInfo.rotationDegrees)
                                codeScanner.process(image)
                                    .addOnSuccessListener { barcodes ->
                                        val raw = barcodes.firstOrNull { !it.rawValue.isNullOrBlank() }?.rawValue
                                        if (raw != null && handled.compareAndSet(false, true)) {
                                            mainHandler.post { importRaw(raw) }
                                        }
                                    }
                                    .addOnCompleteListener { imageProxy.close() }
                            }
                            provider.unbindAll()
                            provider.bindToLifecycle(
                                lifecycleOwner,
                                CameraSelector.DEFAULT_BACK_CAMERA,
                                preview,
                                imageAnalysis,
                            )
                        }.onFailure { cameraError = it.message ?: "相机启动失败" }
                    }, ContextCompat.getMainExecutor(ctx))
                    previewView
                },
                modifier = Modifier.fillMaxSize(),
            )
            // 取景框
            Box(
                Modifier
                    .align(Alignment.Center)
                    .size(230.dp)
                    .border(1.dp, Color.White.copy(alpha = 0.75f), RoundedCornerShape(NamuTokens.RadiusCard)),
            )
            Text(
                "将节点或订阅二维码放入框内",
                color = Color.White,
                fontSize = 13.sp,
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .padding(top = 22.dp)
                    .background(Color(0x99000000), RoundedCornerShape(NamuTokens.RadiusControl))
                    .padding(horizontal = 12.dp, vertical = 7.dp),
            )
            TextAction(
                text = "手动输入",
                color = Color.White,
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 26.dp),
            ) { manual = true }
        } else {
            ManualScanPanel(
                granted = granted,
                text = manualText,
                importing = importing,
                error = cameraError,
                onTextChange = { manualText = it },
                onRetryPermission = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                onImport = { importRaw(manualText) },
            )
        }

        if (cameraError != null && !manual) {
            Column(
                Modifier
                    .align(Alignment.Center)
                    .padding(28.dp)
                    .clip(RoundedCornerShape(NamuTokens.RadiusDialog))
                    .background(NamuColors.Card)
                    .padding(18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text("相机不可用", color = NamuColors.TextMain, fontWeight = FontWeight.SemiBold)
                Text(cameraError ?: "", color = NamuColors.TextSub, fontSize = 12.sp, textAlign = TextAlign.Center)
                TextAction("手动输入") { manual = true }
            }
        }
    }
}

@Composable
private fun ManualScanPanel(
    granted: Boolean,
    text: String,
    importing: Boolean,
    error: String?,
    onTextChange: (String) -> Unit,
    onRetryPermission: () -> Unit,
    onImport: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Rounded.CameraAlt,
            contentDescription = null,
            tint = NamuColors.TextSub,
            modifier = Modifier.size(44.dp),
        )
        Spacer(Modifier.height(10.dp))
        Text(
            if (granted) "手动输入" else "未获得相机权限",
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
            color = NamuColors.TextMain,
        )
        Text(
            "可以手动粘贴节点链接或订阅地址，导入流程与扫码一致。",
            fontSize = 12.sp,
            color = NamuColors.TextSub,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 4.dp, bottom = 14.dp),
        )
        NamuTextField(
            value = text,
            onChange = onTextChange,
            placeholder = "vless://… / vmess://… / ss://… / https://订阅地址",
            maxLines = 4,
        )
        if (!granted) {
            Spacer(Modifier.height(8.dp))
            TextAction("重新授权相机") { onRetryPermission() }
        }
        Spacer(Modifier.height(8.dp))
        IosButton(
            text = if (importing) "导入中…" else "导入",
            onClick = onImport,
            enabled = text.isNotBlank() && !importing,
            loading = importing,
            modifier = Modifier.fillMaxWidth(),
        )
        if (error != null) {
            Text(error, color = NamuColors.Red, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
        }
    }
}
