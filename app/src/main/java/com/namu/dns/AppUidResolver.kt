package com.namu.dns

import android.content.Context

/**
 * 把包名类规则（PROCESS-NAME / APP / APP-NAME）展开成内核认识的 UID 规则。
 *
 * 为什么不把包名表下发给内核：包名到 UID 的映射随安装、卸载、多用户切换变化，
 * 属于 Android 壳层的知识；内核只需要一个稳定的整数维度参与匹配。
 * 因此配置里保留用户写的包名（可读、换机后可重新解析），只在每次下发内核前展开。
 *
 * 进程名可能带子进程后缀（`com.example.app:push`），取冒号前的包名再查。
 */
internal object AppUidResolver {

    /** 包名类规则集合。 */
    val PACKAGE_TYPES = setOf("PROCESS-NAME", "APP", "APP-NAME")

    fun packageName(value: String): String = value.substringBefore(':').trim()

    /** 该规则是否属于「按 App」维度（包名类或数值 UID）。 */
    fun isAppRule(rule: RuleItem): Boolean {
        val t = rule.type.trim().uppercase()
        return t in PACKAGE_TYPES || t == "UID"
    }

    fun uidOf(context: Context, value: String): Int? {
        val pkg = packageName(value)
        if (pkg.isEmpty()) return null
        return runCatching {
            context.packageManager.getApplicationInfo(pkg, 0).uid
        }.getOrNull()
    }

    /**
     * 把一组包名解析成 UID。返回 (已解析 UID 列表, 未解析包名)，用于按 App MITM。
     * 同一 UID 去重；解析失败的包名交给界面提示，而不是静默丢弃。
     */
    fun resolveUids(context: Context, packages: List<String>): Pair<List<Int>, List<String>> {
        val uids = LinkedHashSet<Int>()
        val unresolved = ArrayList<String>()
        for (raw in packages) {
            val pkg = packageName(raw)
            if (pkg.isEmpty()) continue
            val uid = uidOf(context, pkg)
            if (uid == null) unresolved.add(raw) else uids.add(uid)
        }
        return uids.toList() to unresolved
    }

    /**
     * 展开一组规则：包名类规则替换成等价的 UID 规则，其余原样保留。
     * 返回展开后的列表与「未能解析的包名」，后者用于界面提示规则未生效。
     */
    fun expand(
        context: Context,
        rules: List<RuleItem>,
    ): Pair<List<RuleItem>, List<String>> {
        val unresolved = ArrayList<String>()
        val out = ArrayList<RuleItem>(rules.size)
        for (r in rules) {
            if (r.type.trim().uppercase() !in PACKAGE_TYPES) {
                out.add(r)
                continue
            }
            val uid = uidOf(context, r.value)
            if (uid == null) {
                unresolved.add(r.value)
                continue
            }
            out.add(
                r.copy(
                    type = "UID",
                    // 保留原始包名，方便日志与界面回溯「这条 UID 规则原本是谁」
                    value = uid.toString(),
                ),
            )
        }
        return out to unresolved
    }
}
