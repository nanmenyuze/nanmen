package com.namu.dns

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * 金融连接保护：把金融类 UID 下发给内核，在 MITM 判定之前排除。
 *
 * 只负责「哪些 App」。域名硬排除清单在内核 `finance.rs` 内置，避免两侧各维护一份；
 * 未安装的包名解析不到 UID 会被跳过并记日志，不影响其余清单生效。
 *
 * - [FINANCE_PACKAGES]：独立金融 App，整包不走 MITM（这些 App 的内容也不适合解密）。
 * - [MIXED_PACKAGES]：微信/支付宝/QQ 这类混合体，整包不排除——小程序等第三方业务
 *   域名仍可按规则 MITM，只对支付、账号类域名做排除（内核域名清单 + 关键字启发）。
 */
object FinanceProtect {

    /** 种子清单，可后续扩充；解析不到只记日志，不会误伤其他应用。 */
    val FINANCE_PACKAGES: List<String> = listOf(
        "com.unionpay",                 // 云闪付
        "com.icbc.android",             // 工商银行
        "com.abchina.banking",          // 农业银行
        "com.boc.bocapp",               // 中国银行
        "cmb.pb",                       // 招商银行
        "com.bankcomm.Bankcomm",        // 交通银行
        "com.pingan.paces.ccms",        // 平安口袋银行
        "com.hexin.plat.android",       // 同花顺
        "com.eastmoney.android.berlin", // 东方财富
        "com.jd.jrapp",                 // 京东金融
    )

    val MIXED_PACKAGES: List<String> = listOf(
        "com.tencent.mm",               // 微信
        "com.eg.android.AlipayGphone",  // 支付宝
        "com.tencent.mobileqq",         // QQ（QQ 钱包走财付通域名，已被域名清单覆盖）
    )

    fun toJson(context: Context, enabled: Boolean): JSONObject {
        val (financeUids, unresolvedFinance) = AppUidResolver.resolveUids(context, FINANCE_PACKAGES)
        val (mixedUids, unresolvedMixed) = AppUidResolver.resolveUids(context, MIXED_PACKAGES)
        val unresolved = unresolvedFinance + unresolvedMixed
        if (unresolved.isNotEmpty()) {
            android.util.Log.d("NamuFinance", "金融保护：以下包未安装或未解析，已跳过：$unresolved")
        }
        return JSONObject().apply {
            put("enabled", enabled)
            put("uids", JSONArray(financeUids))
            put("mixed_uids", JSONArray(mixedUids))
            put("keyword_skip", true)
        }
    }
}
