package local.aliang.proxy

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.*
import local.aliang.core.mobile.Mobile
import local.aliang.core.mobile.Protector
import local.aliang.core.mobile.Session
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Runs in :tunnel. Native failure cannot take the UI process down. */
class TunnelService : VpnService() {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val stopping = AtomicBoolean(false)
    private var descriptor: ParcelFileDescriptor? = null
    @Volatile private var session: Session? = null
    @Volatile private var state = "idle"
    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.sendingUid != applicationInfo.uid) return
            when (message.what) {
                1 -> try { message.replyTo?.send(Message.obtain(null, 1).apply { data = Bundle().apply { putString("state", state); putInt("pid", Process.myPid()) } }) } catch (_: RemoteException) { }
                2 -> stopTunnel()
            }
        }
    })
    override fun onBind(intent: Intent): IBinder? = if (intent.action == SERVICE_INTERFACE) super.onBind(intent) else messenger.binder
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) { stopTunnel(); return START_NOT_STICKY }
        if (intent?.action != START) { if (state == "idle") stopSelfResult(startId); return START_NOT_STICKY }
        if (state != "idle" || stopping.get()) return START_NOT_STICKY
        state = "starting"
        try { foreground("正在建立隧道") } catch (_: Exception) { stopTunnel(); return START_NOT_STICKY }
        main.postDelayed({ if (state == "starting") stopTunnel() }, 20000)
        worker.execute {
            try {
                val profile = ProfileStore(this).load() ?: error("missing_profile")
                // Validate before allocating the system TUN. No external config is accepted.
                Mobile.inspect(profile.yaml)
                if (stopping.get()) return@execute
                val fd = Builder().setSession("ALiang Proxy").setMtu(1400)
                    .addAddress("172.19.0.1", 30).addAddress("fdfe:dcba:9876::1", 126)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("172.19.0.2")
                    .setBlocking(false).establish() ?: error("vpn_permission_missing")
                synchronized(this) {
                    if (stopping.get()) { fd.close(); return@execute }
                    descriptor = fd
                }
                val created = Mobile.start(profile.yaml, profile.selected, profile.choices, profile.resolver, fd.fd, object : Protector {
                    override fun protect(socket: Int): Boolean = !stopping.get() && this@TunnelService.protect(socket)
                })
                session = created
                if (stopping.get()) { created.close(); session = null; return@execute }
                main.post { if (!stopping.get()) { state = "connected"; foreground("隧道已建立 · 远端连通性由实际访问确认") } }
            } catch (_: Throwable) { main.post { state = "failed"; stopTunnel() } }
        }
        return START_NOT_STICKY
    }
    private fun foreground(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("tunnel", "代理连接", NotificationManager.IMPORTANCE_LOW))
        val stop = PendingIntent.getService(this, 1, Intent(this, TunnelService::class.java).setAction(STOP), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, "tunnel").setSmallIcon(android.R.drawable.stat_sys_upload_done)
            .setContentTitle("ALiang Proxy").setContentText(text).setContentIntent(open).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "停止连接", stop).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(1, notification)
    }
    private fun stopTunnel() {
        if (!stopping.compareAndSet(false, true)) return
        state = "stopping"
        synchronized(this) { try { descriptor?.close() } catch (_: Exception) { }; descriptor = null }
        // Independent main-loop watchdog bounds native shutdown even if JNI hangs.
        // This is only our dedicated VPN process, never the UI or another app.
        main.postDelayed({ Process.killProcess(Process.myPid()) }, 8000)
        worker.execute {
            try { session?.close() } catch (_: Throwable) { }
            finally {
                session = null
                main.post {
                    state = "idle"; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
                    // A bound Activity can retain Service lifetime. End this dedicated
                    // process to remove all native threads/FDs and force a fresh start.
                    Process.killProcess(Process.myPid())
                }
            }
        }
    }
    override fun onRevoke() { stopTunnel(); super.onRevoke() }
    override fun onDestroy() {
        if (!stopping.get()) stopTunnel()
        worker.shutdown()
        super.onDestroy()
    }
    companion object {
        const val START = "local.aliang.proxy.START"
        const val STOP = "local.aliang.proxy.STOP"
    }
}
