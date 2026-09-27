package lantern.protocol
import kotlin.test.*
import lantern.domain.Reconnection
class WireTest {
    private val id = "a".repeat(64)
    @Test fun textValidationCountsBytesAndChecksIdentifiers() {
        val frame = Frame(
            type = FrameType.TEXT,
            sender = id,
            id = "00000000-0000-0000-0000-000000000001",
            session = id,
            body = "é".repeat(4096),
            signature = "test-signature",
        )
        assertEquals(frame, Wire.decode(Wire.encode(frame)))
        assertFails { Wire.decode(Wire.encode(frame.copy(body = frame.body + "x"))) }
        assertFails { Wire.decode(Wire.encode(frame.copy(id = "-".repeat(36)))) }
        assertFails { Wire.decode(Wire.encode(frame.copy(session = "z".repeat(64)))) }
    }
    @Test fun enumKeepsVersionZeroJsonAndSigningContract() {
        val oldJson = """{"version":0,"type":"HELLO","sender":"${id}","nonce":"${id}","id":"","session":"","body":"","signature":""}"""
        val frame = Frame(type = FrameType.HELLO, sender = id, nonce = id)
        assertEquals(frame, Wire.decode(oldJson.encodeToByteArray()))
        assertEquals(oldJson, Wire.encode(frame).decodeToString())
        val fields = listOf("lantern-0", "HELLO", id, "", "", "")
        val legacySigned = fields.joinToString("") { "${it.encodeToByteArray().size}:$it" }
        assertEquals(legacySigned, Wire.signedBytes(frame).decodeToString())
        assertFails { Wire.decode(oldJson.replace("HELLO", "UNKNOWN").encodeToByteArray()) }
    }
    @Test fun strictFrameAndVersion() {
        val f = Frame(type = FrameType.HELLO, sender = id, nonce = "b".repeat(64))
        assertEquals(f, Wire.decode(Wire.encode(f)))
        assertFails { Wire.decode(Wire.encode(f.copy(version = 1))) }
        assertFails { Wire.decode(ByteArray(Wire.MAX_FRAME + 1)) }
        assertFails { Wire.decode("{broken".encodeToByteArray()) }
        assertFails { Wire.decode(Wire.encode(f.copy(nonce = "bad"))) }
    }
    @Test fun transcriptIsSymmetricAndBoundToNonces() {
        assertEquals(Wire.transcript("a", "1", "b", "2"), Wire.transcript("b", "2", "a", "1"))
        assertNotEquals(Wire.transcript("a", "1", "b", "2"), Wire.transcript("a", "3", "b", "2"))
        assertFails { Wire.transcript("a", "1", "a", "2") }
    }
    @Test fun signaturesAreUnambiguous() {
        val a = Frame(type = FrameType.TEXT, sender = id, id = "abc", body = "1:x")
        assertFalse(Wire.signedBytes(a).contentEquals(Wire.signedBytes(a.copy(id = "abc1:", body = "x"))))
    }
    @Test fun reconnectHasBoundAndUniqueInitiator() {
        assertEquals(750, Reconnection.delayMillis(0, 0.0))
        assertEquals(30000, Reconnection.delayMillis(100, 1.0))
        assertTrue(Reconnection.initiates("a", "b")); assertFalse(Reconnection.initiates("b", "a"))
    }
}
