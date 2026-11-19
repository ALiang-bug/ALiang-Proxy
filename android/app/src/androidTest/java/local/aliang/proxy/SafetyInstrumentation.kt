package local.aliang.proxy

import android.app.Instrumentation
import android.content.*
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.*
import local.aliang.core.mobile.Mobile
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject

/** Offline emulator-only acceptance harness. Never imports a real subscription. */
class SafetyInstrumentation : Instrumentation() {
    private val reports = mutableListOf<String>()
    private val handlerThread = HandlerThread("test-replies")
    private var remote: Messenger? = null
    private var connection: ServiceConnection? = null
    private var stateLatch: CountDownLatch? = null
    private var state = "unknown"
    private var pid = -1
    private var dataplane = false
    private var source = fixture
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); dataplane = arguments?.getString("dataplane") == "true"; start() }
    override fun onStart() {
        val result = Bundle()
        var resultCode = 0
        var ownsFixture = false
        try {
            check(Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("sdk") || Build.HARDWARE.contains("ranchu")) { "emulator_only" }
            check(ProfileStore(targetContext).load() == null) { "refuse_existing_profile" }
            handlerThread.start()
            ownsFixture = true
            if (dataplane) source = context.assets.open("offline.yaml").bufferedReader().use { it.readText() }
            storageChecks()
            check(Mobile.inspect(source).contains("test-node")) { "native_inspection_failed" }
            reports += "native JNI inspection passed"
            batchChecks()
            val reply = Messenger(object : Handler(handlerThread.looper) {
                override fun handleMessage(message: Message) { state = message.data.getString("state", "unknown"); pid = message.data.getInt("pid", -1); stateLatch?.countDown() }
            })
            val ready = CountDownLatch(1)
            connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) { remote = Messenger(binder); ready.countDown() }
                override fun onServiceDisconnected(name: ComponentName) { remote = null }
            }
            runOnMainSync {
                targetContext.startActivity(Intent(targetContext, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                check(targetContext.bindService(Intent(targetContext, TunnelService::class.java), connection!!, Context.BIND_AUTO_CREATE))
            }
            check(ready.await(5, TimeUnit.SECONDS)) { "binder_timeout" }
            fun query(): String {
                val latch = CountDownLatch(1); stateLatch = latch
                try { remote?.send(Message.obtain(null, 1).apply { replyTo = reply }) } catch (_: RemoteException) { return "restarting" }
                if (remote == null) return "restarting"
                check(latch.await(3, TimeUnit.SECONDS)) { "query_timeout" }; return state
            }
            check(query() == "idle")
            check(VpnService.prepare(targetContext) == null) { "grant_emulator_VPN_appop_first" }
            Thread.sleep(1000)
            runOnMainSync { targetContext.startForegroundService(Intent(targetContext, TunnelService::class.java).setAction(TunnelService.START)) }
            val until = SystemClock.elapsedRealtime() + 15000
            while (query() != "connected" && SystemClock.elapsedRealtime() < until) Thread.sleep(200)
            check(state == "connected") { "tunnel_not_ready" }
            check(hasVpn()) { "system_VPN_missing" }
            reports += "VPN establishment and system network visible"
            if (dataplane) {
                java.net.Socket().use { socket ->
                    socket.connect(java.net.InetSocketAddress("198.51.100.7", 80), 5000)
                    socket.soTimeout = 5000
                    socket.getOutputStream().write("GET / HTTP/1.1\r\nHost: offline.invalid\r\nConnection: close\r\n\r\n".toByteArray())
                    val response = socket.getInputStream().bufferedReader().use { it.readText() }
                    check(response.contains("ALiang offline path OK")) { "tunnel_HTTP_response_missing" }
                }
                reports += "Full Android application -> system TUN -> Reality/Vision -> loopback HTTP roundtrip passed"
                java.net.DatagramSocket().use { socket ->
                    socket.soTimeout = 5000
                    val payload = "ALiang UDP path".toByteArray()
                    socket.send(java.net.DatagramPacket(payload, payload.size, java.net.InetAddress.getByName("198.51.100.7"), 4242))
                    val reply = java.net.DatagramPacket(ByteArray(256), 256); socket.receive(reply)
                    check(reply.data.copyOf(reply.length).contentEquals(payload)) { "tunnel_UDP_response_missing" }
                }
                reports += "Full Android application -> system TUN -> Reality/Vision -> loopback UDP roundtrip passed"
            }
            runOnMainSync { targetContext.startForegroundService(Intent(targetContext, TunnelService::class.java).setAction(TunnelService.START)) }
            Thread.sleep(500); check(query() == "connected") { "duplicate_start_stopped_tunnel" }
            reports += "duplicate start preserved one live tunnel"
            remote!!.send(Message.obtain(null, 2))
            waitNoVpn()
            reports += "stop removed VPN network"
            fun idleAgain() {
                val untilIdle = SystemClock.elapsedRealtime() + 10000
                while (query() != "idle" && SystemClock.elapsedRealtime() < untilIdle) Thread.sleep(200)
                check(state == "idle") { "service_not_idle_after_stop" }
            }
            fun connectAgain() {
                idleAgain()
                runOnMainSync { targetContext.startForegroundService(Intent(targetContext, TunnelService::class.java).setAction(TunnelService.START)) }
                val readyUntil = SystemClock.elapsedRealtime() + 10000
                while (query() != "connected" && SystemClock.elapsedRealtime() < readyUntil) Thread.sleep(200)
                check(state == "connected" && hasVpn()) { "reconnect_failed" }
            }
            connectAgain()
            check(pid > 0 && pid != Process.myPid()) { "invalid_isolated_PID" }
            Process.killProcess(pid)
            waitNoVpn(); idleAgain(); check(!hasVpn()) { "crash_auto_reconnected" }
            reports += "forced tunnel-process death removed VPN and did not auto-reconnect"
            connectAgain()
            // Closing our own service through the framework revoke path must be
            // idempotent; repeated stops must not leave a second tunnel.
            remote!!.send(Message.obtain(null, 2))
            try { remote?.send(Message.obtain(null, 2)) } catch (_: RemoteException) { }
            waitNoVpn(); idleAgain()
            reports += "reconnect after crash and repeated stop passed"
            connectAgain()
            context.startActivity(Intent().setComponent(ComponentName("local.aliang.proxy.test", "local.aliang.proxy.RevokeActivity")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            waitNoVpn(); idleAgain()
            reports += "system VPN authorization replacement revoked the tunnel cleanly"

            reports += "PASS"
            result.putString("stream", reports.joinToString("\n", postfix = "\n"))

        } catch (e: Throwable) {
            result.putString("stream", reports.joinToString("\n") + "\nFAIL: " + e.javaClass.simpleName + ": " + e.message + "\n")
            resultCode = 1
        } finally {
            try { connection?.let { targetContext.unbindService(it) } } catch (_: Exception) { }
            if (ownsFixture) try { ProfileStore(targetContext).delete() } catch (_: Exception) { }
            handlerThread.quitSafely()
        }
        finish(resultCode, result)
    }
    private fun hasVpn(): Boolean {
        val manager = targetContext.getSystemService(ConnectivityManager::class.java)
        return manager.allNetworks.any { manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    }
    private fun batchChecks() {
        val complete = CountDownLatch(1)
        val returned = AtomicInteger()
        val failures = AtomicInteger()
        // Exercise the exported cancellable JNI object through the real scheduler,
        // cancelling before Run so these checks cannot contact an external target.
        BatchRunner((1..20).map { "$it" }, 2, {
            val job = Mobile.newProbeJob(source, "test-node", "ali", false)
            job.cancel()
            object : BatchRunner.Task<String> {
                override fun run() = job.run()
                override fun cancel() = job.cancel()
            }
        }, { _, value, _ ->
            val result = JSONObject(value)
            if (result.optBoolean("ok") || result.optString("error") != "cancelled") failures.incrementAndGet()
            returned.incrementAndGet()
        }, { cancelled, count ->
            if (cancelled || count != 20) failures.incrementAndGet()
            complete.countDown()
        }).start()
        check(complete.await(5, TimeUnit.SECONDS) && returned.get() == 20 && failures.get() == 0) { "JNI_batch_cancel_failed" }
        reports += "20 real JNI ProbeJob instances completed through bounded batch scheduler with pre-cancellation and no network IO"
    }
    private fun waitNoVpn() {
        val until = SystemClock.elapsedRealtime() + 12000
        while (hasVpn() && SystemClock.elapsedRealtime() < until) Thread.sleep(200)
        check(!hasVpn()) { "VPN_remains_after_stop" }
    }
    private fun storageChecks() {
        val store = ProfileStore(targetContext)
        val profile = SavedProfile(source, "https://example.invalid/sub?token=only-test")
        store.save(profile); check(store.load() == profile) { "encrypted_roundtrip_failed" }
        val file = java.io.File(targetContext.noBackupFilesDir, "profile.enc")
        val bytes = file.readBytes()
        check(!String(bytes, Charsets.ISO_8859_1).contains("only-test")) { "plaintext_secret_on_disk" }
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte(); file.writeBytes(bytes)
        var rejected = false; try { store.load() } catch (_: Exception) { rejected = true }
        check(rejected) { "tamper_not_rejected" }; store.save(profile)
        reports += "Keystore encryption roundtrip, plaintext absence and GCM tamper rejection passed"
    }
    companion object {
        val fixture = """
            proxies:
              - name: test-node
                type: vless
                server: 127.0.0.1
                port: 9
                uuid: 00000000-0000-4000-8000-000000000001
                tls: true
                udp: true
                servername: example.invalid
            proxy-groups:
              - name: default-group
                type: select
                proxies: [test-node]
            rules: ['MATCH,default-group']
        """.trimIndent()
    }
}
