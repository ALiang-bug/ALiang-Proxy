package local.aliang.proxy

import android.app.Activity
import android.net.VpnService
import android.os.Bundle

/** Emulator helper in the separate test APK; never packaged into the client. */
class RevokeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VpnService.prepare(this) // Test APK app-op pre-authorized by the test runner script.
        finish()
    }
}
