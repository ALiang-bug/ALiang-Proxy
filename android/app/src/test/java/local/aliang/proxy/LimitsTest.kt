package local.aliang.proxy

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream

class LimitsTest {
    @Test fun boundedReadRejectsOversize() {
        assertEquals(4, Limits.read(ByteArrayInputStream(ByteArray(4)), 4).size)
        try { Limits.read(ByteArrayInputStream(ByteArray(5)), 4); fail("oversized accepted") } catch (_: IllegalArgumentException) { }
    }
    @Test fun subscriptionBoundary() {
        assertEquals("example.org", Limits.subscription("https://example.org:443/sub?token=private").host)
        for (uri in listOf("http://example.org/sub", "file:///private", "https://user:pass@example.org/sub", "https://example.org/#token", "https://example.org:99999/sub", "https://", "x".repeat(8193))) {
            try { Limits.subscription(uri); fail("unsafe URL accepted") } catch (_: Exception) { }
        }
    }
    @Test fun cancelledReadStops() {
        Thread.currentThread().interrupt()
        try { Limits.read(ByteArrayInputStream(ByteArray(1)), 10); fail("cancel ignored") }
        catch (_: InterruptedException) { }
        finally { Thread.interrupted() }
    }
}
