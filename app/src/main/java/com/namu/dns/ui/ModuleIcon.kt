package com.namu.dns.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Extension
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.namu.dns.ConfigStore
import com.namu.dns.ModuleParser
import com.namu.dns.ModuleSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.net.URISyntaxException
import javax.net.ssl.HttpsURLConnection

private const val MAX_ICON_BYTES = 1024 * 1024
private const val MAX_ICON_DIMENSION = 4096
private val moduleIconCache = LruCache<Pair<String, Long>, Bitmap>(64)

@OptIn(ExperimentalCoroutinesApi::class)
private val moduleIconDispatcher = Dispatchers.IO.limitedParallelism(4)

@Composable
internal fun ModuleIcon(module: ModuleSource) {
    val context = LocalContext.current
    key(module.id, module.iconUrl, module.updatedAt, module.cacheBytes) {
        val bitmap by produceState<Bitmap?>(null) {
            value = withContext(moduleIconDispatcher) {
                try {
                    val address = module.iconUrl?.takeIf { it.isNotBlank() } ?: run {
                        val text = ConfigStore.moduleFile(context, module.id)
                            .takeIf { it.exists() && it.length() > 0L }
                            ?.readText()
                        if (text.isNullOrBlank()) "" else {
                            declaredModuleIconUrl(text)
                                ?: ModuleParser.readIconUrl(text.lineSequence())
                        }
                    }
                    if (address.isBlank()) null else loadModuleIcon(address, iconRevision(module))
                } catch (_: IOException) {
                    null
                } catch (_: URISyntaxException) {
                    null
                } catch (_: IllegalArgumentException) {
                    null
                } catch (_: SecurityException) {
                    null
                }
            }
        }

        val shape = RoundedCornerShape(8.dp)
        val currentBitmap = bitmap
        if (currentBitmap == null) {
            Box(
                modifier = Modifier.size(32.dp).background(NamuColors.Bg, shape),
                contentAlignment = Alignment.Center,
            ) {
                NamuIcon(Icons.Outlined.Extension, tint = NamuColors.TextSub, size = 18.dp)
            }
        } else {
            Image(
                bitmap = currentBitmap.asImageBitmap(),
                contentDescription = null,
                modifier = Modifier.size(32.dp).clip(shape),
                contentScale = ContentScale.Fit,
            )
        }
    }
}

private fun iconRevision(module: ModuleSource): Long =
    if (module.cacheBytes != 0L) module.cacheBytes else module.updatedAt

/** 模块文件可声明 `#!icon = URL`，JSON 模块也接受 icon / iconUrl / icon-url。 */
private fun declaredModuleIconUrl(text: String): String? {
    val trimmed = text.removePrefix("\uFEFF").trimStart()
    val declared = if (trimmed.startsWith("{")) {
        runCatching {
            val json = JSONObject(trimmed)
            sequenceOf(json.optString("icon"), json.optString("iconUrl"), json.optString("icon-url"))
                .firstOrNull { it.isNotBlank() }
        }.getOrNull()
    } else {
        Regex(
            "^#!icon\\s*=\\s*(.+?)\\s*$",
            setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
        ).find(text)?.groupValues?.get(1)
    }
    val candidate = declared?.trim()?.trim('"', '\'')?.takeIf { it.length <= 2048 } ?: return null
    return runCatching {
        URI(candidate).takeIf {
            it.scheme.equals("https", ignoreCase = true) &&
                !it.host.isNullOrBlank() &&
                it.userInfo == null
        }?.toString()
    }.getOrNull()
}

private fun loadModuleIcon(address: String, revision: Long): Bitmap? {
    val cacheKey = address to revision
    moduleIconCache.get(cacheKey)?.let { return it }

    var uri = URI(address)
    repeat(4) {
        if (!uri.scheme.equals("https", ignoreCase = true) || uri.host.isNullOrBlank() || uri.userInfo != null) {
            return null
        }
        val connection = uri.toURL().openConnection() as HttpsURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.setRequestProperty("Accept", "image/*")
        connection.setRequestProperty("User-Agent", "NamuDNS/3.0.5")
        try {
            when (connection.responseCode) {
                301, 302, 303, 307, 308 -> {
                    val location = connection.getHeaderField("Location") ?: return null
                    uri = uri.resolve(location)
                }
                200 -> {
                    if (connection.contentLengthLong > MAX_ICON_BYTES) return null
                    val bytes = connection.inputStream.buffered().use { input ->
                        val output = ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (count == 0) continue
                            if (output.size() + count > MAX_ICON_BYTES) return null
                            output.write(buffer, 0, count)
                        }
                        output.toByteArray()
                    }
                    return decodeModuleIcon(bytes)?.also { moduleIconCache.put(cacheKey, it) }
                }
                else -> return null
            }
        } finally {
            connection.disconnect()
        }
    }
    return null
}

private fun decodeModuleIcon(bytes: ByteArray): Bitmap? {
    if (bytes.isEmpty()) return null
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    if (bounds.outWidth > MAX_ICON_DIMENSION || bounds.outHeight > MAX_ICON_DIMENSION) return null

    var sampleSize = 1
    while (bounds.outWidth / sampleSize > 256 || bounds.outHeight / sampleSize > 256) {
        sampleSize *= 2
    }
    val options = BitmapFactory.Options().apply { inSampleSize = sampleSize }
    return BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
}
