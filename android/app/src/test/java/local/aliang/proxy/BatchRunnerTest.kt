package local.aliang.proxy

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class BatchRunnerTest {
    @Test fun boundsConcurrencyAndCompletesEveryNode() {
        val active = AtomicInteger(); val peak = AtomicInteger(); val done = CountDownLatch(1)
        val results = ConcurrentHashMap.newKeySet<String>()
        val runner = BatchRunner((1..40).map { "$it" }, 99, { name -> object : BatchRunner.Task<String> {
            override fun run(): String {
                val n = active.incrementAndGet(); peak.accumulateAndGet(n, ::maxOf)
                try { Thread.sleep(2); return name } finally { active.decrementAndGet() }
            }
            override fun cancel() { }
        } }, { name, _, _ -> results.add(name) }, { cancelled, count ->
            assertFalse(cancelled); assertEquals(40, count); done.countDown()
        })
        runner.start(); assertTrue(done.await(3, TimeUnit.SECONDS)); assertEquals(40, results.size); assertTrue(peak.get() <= 2)
    }
    @Test fun cancelInterruptsActiveWorkAndDoesNotScheduleRemainder() {
        val started = CountDownLatch(2); val done = CountDownLatch(1)
        val created = AtomicInteger(); val delivered = AtomicInteger()
        val runner = BatchRunner((1..200).map { "$it" }, 2, { object : BatchRunner.Task<String> {
            val stop = CountDownLatch(1)
            init { created.incrementAndGet() }
            override fun run(): String { started.countDown(); check(stop.await(3, TimeUnit.SECONDS)); return "cancelled" }
            override fun cancel() { stop.countDown() }
        } }, { _, _, _ -> delivered.incrementAndGet() }, { cancelled, _ -> assertTrue(cancelled); done.countDown() })
        runner.start(); assertTrue(started.await(1, TimeUnit.SECONDS)); runner.cancel(); runner.cancel()
        assertTrue(done.await(1, TimeUnit.SECONDS)); assertEquals(2, created.get()); assertEquals(0, delivered.get())
    }
    @Test fun serialDownloadModeAndEmptyInputFinish() {
        val done = CountDownLatch(1)
        BatchRunner<String>(emptyList(), 1, { error("empty input created a job") }, { _, _, _ -> error("unexpected result") }, { cancelled, count -> assertFalse(cancelled); assertEquals(0, count); done.countDown() }).start()
        assertTrue(done.await(1, TimeUnit.SECONDS))
        val serialDone = CountDownLatch(1); val active = AtomicInteger(); val peak = AtomicInteger()
        BatchRunner((1..6).map { "$it" }, 1, { object : BatchRunner.Task<Int> {
            override fun run(): Int { val n = active.incrementAndGet(); peak.accumulateAndGet(n, ::maxOf); active.decrementAndGet(); return n }
            override fun cancel() { }
        } }, { _, _, _ -> }, { _, _ -> serialDone.countDown() }).start()
        assertTrue(serialDone.await(1, TimeUnit.SECONDS)); assertEquals(1, peak.get())
    }
}
