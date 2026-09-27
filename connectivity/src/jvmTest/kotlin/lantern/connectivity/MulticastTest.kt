package lantern.connectivity

import kotlin.test.*
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap
import org.junit.Assume.assumeTrue

class MulticastTest {
    @Test fun realMdnsOnSelectedInterface() {
        assumeTrue("Opt-in: -Dlantern.multicast=true passed via Gradle property", System.getProperty("lantern.multicast") == "true")
        val address = NetworkInterface.getNetworkInterfaces().toList().filter { it.isUp && !it.isLoopback && it.supportsMulticast() }
            .flatMap { it.inetAddresses.toList() }.first { it is Inet4Address && it.isSiteLocalAddress }
        val a = LanDiscovery(address); val b = LanDiscovery(address)
        val seenA = ConcurrentHashMap.newKeySet<String>(); val seenB = ConcurrentHashMap.newKeySet<String>()
        try {
            a.start("Probe A", "a".repeat(64), 32101, { seenA.add(it.id) }, { seenA.remove(it) })
            b.start("Probe B", "b".repeat(64), 32102, { seenB.add(it.id) }, { seenB.remove(it) })
            val until = System.currentTimeMillis() + 20000
            while ((seenA.isEmpty() || seenB.isEmpty()) && System.currentTimeMillis() < until) Thread.sleep(100)
            assertTrue("b".repeat(64) in seenA, "A must discover B over real multicast")
            assertTrue("a".repeat(64) in seenB, "B must discover A over real multicast")
        } finally { a.stop(); b.stop() }
    }
}
