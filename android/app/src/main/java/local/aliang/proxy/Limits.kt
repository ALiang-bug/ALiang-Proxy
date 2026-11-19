package local.aliang.proxy

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URI
import javax.net.ssl.HttpsURLConnection

object Limits {
    const val PROFILE_BYTES = 1024 * 1024
    const val ENVELOPE_BYTES = PROFILE_BYTES * 6 + 65536
    fun read(input: InputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        val deadline = System.nanoTime() + 30_000_000_000L
        while (true) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException()
            require(System.nanoTime() <= deadline) { "read_deadline_exceeded" }
            val n = input.read(buffer)
            if (n < 0) break
            require(n <= limit - output.size()) { "input_too_large" }
            output.write(buffer, 0, n)
        }
        return output.toByteArray()
    }
    fun subscription(raw: String): URI {
        require(raw.length <= 8192)
        val uri = URI(raw)
        require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawFragment == null)
        require(uri.port == -1 || uri.port in 1..65535)
        return uri
    }
    fun download(raw: String): String {
        val connection = subscription(raw).toURL().openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 12000; connection.readTimeout = 12000
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("User-Agent", "ALiangProxy/0.1.1 (ClashMeta compatible import)")
            connection.setRequestProperty("Accept-Encoding", "identity")
            require(connection.responseCode == 200)
            require(connection.contentLengthLong <= PROFILE_BYTES)
            return connection.inputStream.use { String(read(it, PROFILE_BYTES), Charsets.UTF_8) }
        } finally { connection.disconnect() }
    }
    /** Uses Android's default app route, intentionally without VPN protection. */
    fun checkTunnel() {
        val connection = java.net.URL("https://www.apple.com/library/test/success.html").openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 6000; connection.readTimeout = 6000
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Cache-Control", "no-cache")
            connection.setRequestProperty("Accept-Encoding", "identity")
            require(connection.responseCode == 200)
            val body = connection.inputStream.use { String(read(it, 4096), Charsets.UTF_8) }
            require(body.contains("Success"))
        } finally { connection.disconnect() }
    }

}
