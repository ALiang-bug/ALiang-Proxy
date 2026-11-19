package local.aliang.proxy

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Bounded workers pull jobs lazily: no queue of thousands of native instances. */
class BatchRunner<T>(
    private val names: List<String>, concurrency: Int,
    private val factory: (String) -> Task<T>,
    private val result: (String, T, Int) -> Unit,
    private val finished: (Boolean, Int) -> Unit
) {
    interface Task<T> { fun run(): T; fun cancel() }
    private val count = concurrency.coerceIn(1, 2).coerceAtMost(names.size.coerceAtLeast(1))
    private val pool = Executors.newFixedThreadPool(count)
    private val cancelled = AtomicBoolean(false)
    private val started = AtomicBoolean(false)
    private val next = AtomicInteger()
    private val done = AtomicInteger()
    private val live = AtomicInteger(count)
    private val active = ConcurrentHashMap<Int, Task<T>>()
    fun start() {
        check(started.compareAndSet(false, true))
        repeat(count) { worker -> pool.execute {
            try {
                while (!cancelled.get()) {
                    val index = next.getAndIncrement()
                    if (index >= names.size) break
                    val task = factory(names[index]); active[worker] = task
                    try {
                        if (cancelled.get()) { task.cancel(); break }
                        val value = task.run()
                        if (!cancelled.get()) {
                            val completed = done.incrementAndGet()
                            result(names[index], value, completed)
                        }
                    } finally { active.remove(worker); task.cancel() }
                }
            } catch (_: Exception) { cancel() }
            finally {
                if (live.decrementAndGet() == 0) { pool.shutdown(); finished(cancelled.get(), done.get()) }
            }
        } }
    }
    fun isCancelled(): Boolean = cancelled.get()
    fun cancel() {
        cancelled.set(true)
        active.values.forEach { try { it.cancel() } catch (_: Exception) { } }
    }
}
