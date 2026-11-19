package local.aliang.proxy

import android.Manifest
import android.app.*
import android.content.*
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.*
import android.text.InputType
import android.view.*
import android.widget.*
import local.aliang.core.mobile.Mobile
import org.json.JSONObject
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var profile: SavedProfile? = null
    private var info: JSONObject? = null
    private var remote: Messenger? = null
    private var bound = false
    private var visible = false
    private var busy = true
    private var state = "checking"
    private lateinit var status: TextView
    private lateinit var connect: Button
    private lateinit var url: EditText
    private var pathTest = "联网尚未验证"
    private var pathCheck: Button? = null
    private var batch: BatchRunner<JSONObject>? = null
    private var batchDone = 0
    private var batchTotal = 0
    private var batchCaption = "未执行批量测试"
    private var batchNetwork = 0L
    private var batchStatus: TextView? = null
    private var batchProgress: ProgressBar? = null
    private var batchCancel: Button? = null
    private var resultContainer: LinearLayout? = null
    private val resultActions = mutableListOf<Button>()
    private var sortSpeed = false
    private var refreshScheduled = false
    private val refreshResults = Runnable { refreshScheduled = false; if (!isDestroyed && visible) renderResults() }
    private val guarded = mutableListOf<View>()
    private val probeResults = linkedMapOf<String, JSONObject>()
    private val cyan = Color.rgb(22, 208, 211)
    private val replies = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.what == 1) { state = message.data.getString("state", "idle"); updateState() }
        }
    })
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) { remote = Messenger(binder); poll() }
        override fun onServiceDisconnected(name: ComponentName) {
            val unexpected = state == "connected" || state == "starting"
            remote = null; state = "checking"; updateState()
            if (unexpected && visible) notice("隧道进程已退出，Android 会释放该隧道。请检查节点和系统 VPN 设置后重新连接；应用不会自动重连。")
            if (bound) { unbindService(this); bound = false }
            main.postDelayed({ if (visible) bindTunnel() }, 500)
        }
        override fun onBindingDied(name: ComponentName) = onServiceDisconnected(name)
    }
    private val ticker = object : Runnable {
        override fun run() { if (visible) {
            poll()
            if (batch != null && (state != "idle" || anotherVpn() || currentNetwork() != batchNetwork)) cancelBatch()
            main.postDelayed(this, 1000)
        } }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = Color.rgb(15, 20, 28)
        window.navigationBarColor = Color.rgb(15, 20, 28)
        render()
        work {
            val stored = ProfileStore(this).load()
            val metadata = stored?.let { JSONObject(Mobile.inspect(it.yaml)) }
            main.post { if (!isDestroyed) { profile = stored; info = metadata; render() } }
        }
    }
    override fun onStart() { super.onStart(); visible = true; bindTunnel(); main.post(ticker) }
    override fun onStop() {
        visible = false; main.removeCallbacks(ticker); main.removeCallbacks(refreshResults); refreshScheduled = false; cancelBatch()
        if (bound) { unbindService(connection); bound = false }; remote = null
        super.onStop()
    }
    override fun onDestroy() { batch?.cancel(); worker.shutdownNow(); super.onDestroy() }
    private fun bindTunnel() {
        if (!bound) bound = bindService(Intent(this, TunnelService::class.java), connection, BIND_AUTO_CREATE)
    }
    private fun poll() {
        try { remote?.send(Message.obtain(null, 1).apply { replyTo = replies }) }
        catch (_: RemoteException) { state = "checking"; updateState() }
    }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
    private fun text(value: String, size: Float = 15f, color: Int = Color.LTGRAY) = TextView(this).apply {
        text = value; textSize = size; setTextColor(color); setPadding(0, dp(7), 0, dp(7))
    }
    private fun column() = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    private fun card(root: LinearLayout, title: String, subtitle: String): LinearLayout {
        val box = column().apply {
            setPadding(dp(18), dp(14), dp(18), dp(18))
            background = GradientDrawable().apply { setColor(Color.rgb(28, 36, 47)); cornerRadius = dp(20).toFloat() }
        }
        root.addView(box, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(18) })
        box.addView(text(title, 21f, Color.WHITE).apply { setTypeface(null, Typeface.BOLD) })
        box.addView(text(subtitle, 13f)); return box
    }
    private fun button(parent: LinearLayout, title: String, guard: Boolean = true, action: () -> Unit): Button {
        val button = Button(this).apply {
            text = title; isAllCaps = false; textSize = 15f
            setTextColor(Color.rgb(10, 25, 31)); backgroundTintList = android.content.res.ColorStateList.valueOf(cyan)
            setOnClickListener { action() }
        }
        parent.addView(button, LinearLayout.LayoutParams(-1, dp(54)).apply { topMargin = dp(8) })
        if (guard) guarded.add(button)
        return button
    }
    private fun render() {
        guarded.clear(); resultContainer = null; batchStatus = null; batchProgress = null; batchCancel = null
        val root = column().apply { setPadding(dp(18), dp(28), dp(18), dp(24)); setBackgroundColor(Color.rgb(15, 20, 28)) }
        val header = LinearLayout(this).apply { gravity = Gravity.CENTER_VERTICAL }
        val iconId = R.drawable.brand_icon
        if (iconId != 0) header.addView(ImageView(this).apply { setImageResource(iconId) }, LinearLayout.LayoutParams(dp(58), dp(58)))
        header.addView(text("ALiang Proxy", 29f, Color.WHITE).apply { setPadding(dp(12), 0, 0, 0); setTypeface(null, Typeface.BOLD) })
        root.addView(header)
        root.addView(text("私人连接 · 配置仅保存在本机", 14f))
        val imports = card(root, "01  导入订阅", "支持 Clash YAML；不会执行配置中的控制端口、脚本或远程规则。")
        url = EditText(this).apply {
            hint = "粘贴 HTTPS 订阅链接"; setHintTextColor(Color.GRAY); setTextColor(Color.WHITE)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO; setSingleLine(true)
        }
        imports.addView(url); guarded.add(url)
        button(imports, "导入订阅") {
            val link = url.text.toString().trim()
            try { Limits.subscription(link) } catch (_: Exception) { notice("请输入有效的 HTTPS 订阅链接。"); return@button }
            confirm("下载订阅", "将直接访问你输入的订阅地址。链接及节点凭据只加密保存在本机。") { importUrl(link) }
        }
        button(imports, "选择本地 YAML 文件") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply { type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE) }, FILE_REQUEST)
        }
        info?.let { imports.addView(text("已载入 ${it.getJSONArray("nodes").length()} 个节点 · ${it.getJSONObject("groups").length()} 个策略组", 15f, cyan)) }
        if (profile != null) {
            button(imports, "更新订阅") {
                val link = profile?.url.orEmpty()
                if (link.isEmpty()) notice("此配置来自文件，请重新选择文件更新。")
                else confirm("更新订阅", "将重新访问原订阅地址；下载或解析失败时保留当前配置。") { importUrl(link) }
            }
            button(imports, "删除本机配置") { confirm("删除配置", "删除本机加密配置，不影响服务商账户。") {
                work { ProfileStore(this).delete(); main.post { profile = null; info = null; probeResults.clear(); render() } }
            } }
        }
        val tunnel = card(root, "02  VPN（TUN）连接", "启动即开启系统 TUN · Wi-Fi / 蜂窝网络 · 全局代理")
        status = text("正在检查连接状态", 17f, cyan); tunnel.addView(status)
        tunnel.addView(text("出口：${profile?.selected?.ifEmpty { info?.optString("default").orEmpty() } ?: "尚未导入"}"))
        button(tunnel, "选择默认出口") { chooseExit() }
        button(tunnel, "策略组选择") { chooseGroup() }
        button(tunnel, "节点域名解析：${if (profile?.resolver == "cloudflare") "Cloudflare DoH" else "阿里 DoH"}") {
            AlertDialog.Builder(this).setTitle("节点域名解析服务").setItems(arrayOf("阿里 DoH · 223.5.5.5", "Cloudflare DoH · 1.1.1.1")) { _, index ->
                profile?.let { save(it.copy(resolver = if (index == 0) "ali" else "cloudflare")) }
            }.show()
        }
        connect = button(tunnel, "启动 VPN（TUN）", false) { toggle() }
        pathCheck = button(tunnel, "验证 TUN 网页访问", false) {
            if (state != "connected" || busy) return@button
            confirm("验证系统 TUN", "将通过当前 VPN 访问 Apple HTTPS 测试页，验证 DNS 和网页转发。此验证与节点测速不同，会消耗少量订阅流量。") {
                if (state != "connected" || busy) return@confirm
                work {
                    val outcome = try {
                        Limits.checkTunnel()
                        "网页验证成功"
                    } catch (_: java.net.UnknownHostException) { "域名解析失败" }
                      catch (_: javax.net.ssl.SSLException) { "HTTPS 校验失败" }
                      catch (_: java.net.SocketTimeoutException) { "网页访问超时" }
                      catch (_: Exception) { "网页验证失败" }
                    main.post { if (!isDestroyed && state == "connected") { pathTest = outcome; updateState(); notice(outcome) } }
                }
            }
        }
        tunnel.addView(text("首次连接需同意系统 VPN 请求。停止连接或隧道进程退出后，由 Android 撤销该隧道。应用不修改永久系统代理；不自动开启始终开启 VPN 或断网保护。", 13f))
        val tests = card(root, "03  节点表现", "先比较可达性与延迟，再按需下载测速。测试仅在 VPN 停止时运行，不经过系统 TUN。")
        button(tests, "批量测试连通性 / 延迟") { startBatch(nodeNames(), false) }
        button(tests, "批量下载测速") { chooseBatchDownload() }
        button(tests, "测试单个节点") { chooseProbe(false) }
        button(tests, "单节点下载测速") { chooseProbe(true) }
        batchStatus = text(batchCaption, 14f, cyan).also { tests.addView(it) }
        batchProgress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).also {
            it.max = batchTotal.coerceAtLeast(1); it.progress = batchDone
            it.progressTintList = android.content.res.ColorStateList.valueOf(cyan); tests.addView(it)
        }
        batchCancel = button(tests, "取消当前批量测试", false) { cancelBatch() }
        button(tests, "排序：低延迟优先", false) { sortSpeed = false; renderResults() }
        button(tests, "排序：高下载速度优先", false) { sortSpeed = true; renderResults() }
        resultContainer = column().also { tests.addView(it) }
        renderResults()
        tests.addView(text("延迟通过节点访问 Apple HTTPS 页面；下载访问 Cloudflare，单次最多约 5 MiB 加协议开销。不会自动测试，不代表实时带宽。延迟测试最多并发 2 个节点；下载测试逐个进行，避免互相抢带宽。结果展示前 100 项，排序只使用实际测试值。", 13f))
        val report = card(root, "04  导入兼容性", "首版使用统一默认出口，策略组可手动选择。")
        report.addView(text("支持 VLESS Reality / Vision、Trojan。订阅内的域名/IP 分流、Fake-IP、远程规则集、桌面 TUN 和 DIRECT 选项停用；不会静默下载外部资源。", 14f))
        report.addView(text("如果某个节点不可达，请换用已确认可用的节点；界面“已连接”仅表示本机隧道建立。", 13f))
        val help = card(root, "连接与恢复", "无需 Root，也无需另装运行环境。")
        button(help, "打开系统 VPN 设置", false) { try { startActivity(Intent("android.settings.VPN_SETTINGS")) } catch (_: Exception) { notice("请在系统设置中搜索 VPN。") } }
        help.addView(text("若系统另行启用了“始终开启 VPN / 阻止未使用 VPN 的连接”，停止应用后仍可能断网，请到系统 VPN 设置检查。应用不会替你开启这些选项。", 13f))
        root.addView(text("ALiang Proxy / Android · 本机加密存储 · 不自动连接", 12f))
        setContentView(ScrollView(this).apply { isFillViewport = true; addView(root) })
        updateState()
    }
    private fun updateState() {
        if (!::status.isInitialized) return
        val idle = state == "idle"
        status.text = when (state) { "idle" -> "待连接"; "starting" -> "正在建立隧道…"; "connected" -> "TUN 已开启 · $pathTest"; "stopping" -> "正在停止并释放隧道…"; "failed" -> "连接失败，正在清理"; else -> "正在检查连接状态…" }
        guarded.forEach { it.isEnabled = idle && !busy }
        resultActions.forEach { it.isEnabled = idle && !busy }
        connect.isEnabled = (state == "connected" || state == "starting") || (!busy && idle && profile != null)
        pathCheck?.isEnabled = state == "connected" && !busy
        batchCancel?.isEnabled = batch != null
        batchStatus?.text = batchCaption
        batchProgress?.max = batchTotal.coerceAtLeast(1)
        batchProgress?.progress = batchDone
        if (idle) pathTest = "联网尚未验证"
        connect.text = if (state == "connected" || state == "starting") "停止 VPN（TUN）" else "启动 VPN（TUN）"
    }
    private fun toggle() {
        if (state == "connected" || state == "starting") {
            try { remote?.send(Message.obtain(null, 2)); state = "stopping"; updateState() } catch (_: RemoteException) { poll() }; return
        }
        if (profile == null || busy || state != "idle") return
        if (anotherVpn()) { notice("检测到其他 VPN，请先关闭后再连接。"); return }
        confirm("建立 VPN 连接", "连接将使用所选节点处理手机流量，并通过所选 DoH 服务解析节点域名。请确认其他 VPN 已关闭。") {
            val prepare = VpnService.prepare(this)
            if (prepare != null) startActivityForResult(prepare, VPN_REQUEST) else startTunnel()
        }
    }
    private fun startTunnel() {
        try {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 3)
            startForegroundService(Intent(this, TunnelService::class.java).setAction(TunnelService.START))
            state = "starting"; updateState()
        } catch (_: Exception) { notice("无法启动 VPN。请检查系统 VPN 授权，并关闭其他 VPN 后重试。"); poll() }
    }
    @Deprecated("Framework activity results")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) return
        if (requestCode == VPN_REQUEST) startTunnel()
        if (requestCode == FILE_REQUEST) data?.data?.let { uri -> work {
            val source = contentResolver.openInputStream(uri)?.use { String(Limits.read(it, Limits.PROFILE_BYTES), Charsets.UTF_8) } ?: error("empty_file")
            stage(SavedProfile(source))
        } }
    }
    private fun importUrl(link: String) = work { stage(SavedProfile(Limits.download(link), link)) }
    private fun stage(candidate: SavedProfile) {
        val metadata = JSONObject(Mobile.inspect(candidate.yaml))
        main.post { if (!isDestroyed) confirm("激活配置", "识别到 ${metadata.getJSONArray("nodes").length()} 个节点、${metadata.getJSONObject("groups").length()} 个策略组。使用全局代理；域名/IP 分流、远程规则、DIRECT 选项与原 DNS 策略停用。") {
            work { ProfileStore(this).save(candidate); main.post { profile = candidate; info = metadata; probeResults.clear(); render() } }
        } }
    }
    private fun save(candidate: SavedProfile) = work { ProfileStore(this).save(candidate); main.post { if (candidate.resolver != profile?.resolver) probeResults.clear(); profile = candidate; render() } }
    private fun chooseExit() {
        val metadata = info ?: return
        val names = mutableListOf<String>()
        val groups = metadata.getJSONObject("groups"); groups.keys().forEach { names.add(it) }
        val nodes = metadata.getJSONArray("nodes"); for (i in 0 until nodes.length()) names.add(nodes.getString(i))
        AlertDialog.Builder(this).setTitle("默认出口").setItems(names.toTypedArray()) { _, index -> profile?.let { save(it.copy(selected = names[index])) } }.show()
    }
    private fun anotherVpn(): Boolean {
        val manager = getSystemService(ConnectivityManager::class.java)
        return manager.allNetworks.any { manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    }
    private fun nodeNames(): List<String> {
        val nodes = info?.getJSONArray("nodes") ?: return emptyList()
        return (0 until nodes.length()).map { nodes.getString(it) }
    }
    private fun currentNetwork(): Long = getSystemService(ConnectivityManager::class.java).activeNetwork?.networkHandle ?: 0L
    private fun chooseProbe(speed: Boolean) {
        val names = nodeNames()
        AlertDialog.Builder(this).setTitle(if (speed) "选择下载测速节点" else "选择连通性测试节点").setItems(names.toTypedArray()) { _, index -> startBatch(listOf(names[index]), speed) }.show()
    }
    private fun chooseBatchDownload() {
        val names = nodeNames()
        val reachable = names.filter { probeResults[it]?.optBoolean("ok") == true }
        val choices = arrayOf("仅本次已连通节点（${reachable.size}）", "全部节点（${names.size}）", "自选节点…")
        AlertDialog.Builder(this).setTitle("批量下载测速范围").setItems(choices) { _, index ->
            when (index) {
                0 -> if (reachable.isEmpty()) notice("请先运行批量连通性测试。") else startBatch(reachable, true)
                1 -> startBatch(names, true)
                else -> {
                    val selected = BooleanArray(names.size)
                    AlertDialog.Builder(this).setTitle("选择测速节点").setMultiChoiceItems(names.toTypedArray(), selected) { _, which, checked -> selected[which] = checked }
                        .setNegativeButton("取消", null).setPositiveButton("继续") { _, _ -> startBatch(names.filterIndexed { i, _ -> selected[i] }, true) }.show()
                }
            }
        }.show()
    }
    private fun startBatch(names: List<String>, speed: Boolean) {
        if (names.isEmpty()) { notice("请至少选择一个节点。"); return }
        if (state != "idle" || busy || batch != null) { notice("请先停止 VPN 或等待当前操作结束。"); return }
        if (anotherVpn()) { notice("请先关闭其他 VPN，避免测试结果受其他代理影响。"); return }
        val details = if (speed) "逐个访问 Cloudflare，每节点最多约 5 MiB，总计最多约 ${names.size.toLong() * 5} MiB，另有协议及节点解析开销。" else "每个节点访问 Apple HTTPS 页面，最多并发 2 项，会消耗少量订阅流量。"
        confirm("测试 ${names.size} 个节点", details + "测试不经过系统 TUN；可随时取消，离开页面或切换网络时自动取消。") {
            if (state != "idle" || busy || !visible || anotherVpn()) return@confirm
            val snapshot = profile ?: return@confirm
            busy = true; batchDone = 0; batchTotal = names.size; batchNetwork = currentNetwork()
            batchCaption = "${if (speed) "下载测速" else "连通性测试"}：0 / $batchTotal"
            lateinit var run: BatchRunner<JSONObject>
            run = BatchRunner(names, if (speed) 1 else 2, { name ->
                val job = Mobile.newProbeJob(snapshot.yaml, name, snapshot.resolver, speed)
                object : BatchRunner.Task<JSONObject> {
                    override fun run(): JSONObject = try { JSONObject(job.run()) } catch (_: Exception) { JSONObject().put("ok", false).put("error", "probe_failed") }
                    override fun cancel() = job.cancel()
                }
            }, { name, value, completed -> main.post {
                if (!isDestroyed && batch === run && visible && !run.isCancelled()) {
                    mergeResult(name, value, speed); batchDone = maxOf(batchDone, completed)
                    batchCaption = "${if (speed) "下载测速" else "连通性测试"}：$batchDone / $batchTotal"
                    updateState()
                    if (!refreshScheduled) { refreshScheduled = true; main.postDelayed(refreshResults, 250) }
                }
            } }, { cancelled, completed -> main.post {
                if (!isDestroyed && batch === run) {
                    batch = null; busy = false; batchDone = completed
                    batchCaption = "${if (cancelled) "已取消" else "已完成"}：$completed / $batchTotal"
                    if (speed) sortSpeed = true
                    renderResults(); updateState()
                }
            } })
            batch = run; updateState(); run.start()
        }
    }
    private fun cancelBatch() {
        batch?.let { batchCaption = "正在取消并释放测试连接…"; it.cancel(); updateState() }
    }
    private fun mergeResult(name: String, result: JSONObject, speed: Boolean) {
        val stored = probeResults[name] ?: JSONObject()
        val ok = result.optBoolean("ok")
        stored.put(if (speed) "speedOK" else "latencyOK", ok)
        stored.put(if (speed) "speedAt" else "latencyAt", System.currentTimeMillis())
        val key = if (speed) "MBps" else "delayMS"
        // Go omits a zero-valued delayMS; a sub-millisecond success is valid.
        if (ok) stored.put(key, if (speed) result.getDouble(key) else result.optLong(key, 0L)) else stored.remove(key)
        stored.put("ok", stored.optBoolean("latencyOK") || stored.optBoolean("speedOK"))
        probeResults[name] = stored
    }
    private fun renderResults() {
        val box = resultContainer ?: return
        box.removeAllViews(); resultActions.clear()
        val sorted = probeResults.entries.sortedWith(compareBy<Map.Entry<String, JSONObject>> {
            if (sortSpeed) -it.value.optDouble("MBps", -1.0) else it.value.optDouble("delayMS", Double.MAX_VALUE)
        }.thenBy { it.key }).take(100)
        for ((name, value) in sorted) {
            box.addView(text(name, 15f, Color.WHITE))
            val lastTime = maxOf(value.optLong("latencyAt"), value.optLong("speedAt"))
            if (lastTime > 0) box.addView(text("最近测试 " + android.text.format.DateFormat.format("HH:mm:ss", lastTime), 12f))
            val latency = if (value.has("delayMS")) "${value.getLong("delayMS")} ms" else if (value.has("latencyOK")) "延迟测试失败" else "延迟未测试"
            val speed = if (value.has("MBps")) "%.2f MB/s".format(value.getDouble("MBps")) else if (value.has("speedOK")) "下载测试失败" else "下载未测试"
            box.addView(text("$latency · $speed", 14f, if (value.optBoolean("ok")) cyan else Color.LTGRAY))
            if ((sortSpeed && value.has("MBps")) || (!sortSpeed && value.has("delayMS"))) {
                val fraction = if (sortSpeed) value.getDouble("MBps") / sorted.maxOf { it.value.optDouble("MBps", 0.0) }.coerceAtLeast(0.000001)
                    else (sorted.minOf { it.value.optDouble("delayMS", Double.MAX_VALUE) }.coerceAtLeast(1.0) / value.getDouble("delayMS").coerceAtLeast(1.0))
                box.addView(ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply { max = 100; progress = (fraction * 100).toInt().coerceIn(1, 100); progressTintList = android.content.res.ColorStateList.valueOf(cyan) })
            }
            if (value.optBoolean("ok")) {
                val use = button(box, if (profile?.selected == name) "当前默认出口" else "选用此节点", false) {
                    if (state == "idle" && !busy) profile?.let { save(it.copy(selected = name)) }
                }
                use.isEnabled = state == "idle" && !busy; resultActions.add(use)
            }
        }
    }
    private fun chooseGroup() {
        val groups = info?.getJSONObject("groups") ?: return
        val names = groups.keys().asSequence().toList()
        AlertDialog.Builder(this).setTitle("选择策略组").setItems(names.toTypedArray()) { _, index ->
            val name = names[index]; val array = groups.getJSONArray(name)
            val members = (0 until array.length()).map { array.getString(it) }
            AlertDialog.Builder(this).setTitle(name).setItems(members.toTypedArray()) { _, choice ->
                profile?.let { val selections = JSONObject(it.choices).put(name, members[choice]); save(it.copy(choices = selections.toString())) }
            }.show()
        }.show()
    }
    private fun work(action: () -> Unit) {
        if (worker.isShutdown) return
        busy = true; updateState()
        worker.execute {
            try { action() }
            catch (_: Exception) { main.post { if (!isDestroyed) notice("操作未完成。请检查文件格式、订阅地址、证书和网络。原有效配置会保留；详细凭据不会写入日志。") } }
            finally { main.post { if (!isDestroyed) { busy = false; updateState() } } }
        }
    }
    private fun notice(message: String) { if (!isFinishing && !isDestroyed) AlertDialog.Builder(this).setTitle("提示").setMessage(message).setPositiveButton("好", null).show() }
    private fun confirm(title: String, message: String, action: () -> Unit) {
        if (!isFinishing && !isDestroyed) AlertDialog.Builder(this).setTitle(title).setMessage(message).setNegativeButton("取消", null).setPositiveButton("继续") { _, _ -> action() }.show()
    }
    companion object { private const val VPN_REQUEST = 1; private const val FILE_REQUEST = 2 }
}
