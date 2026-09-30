package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

class TextWireTest {
    private val sender = "a".repeat(64)
    private val session = "b".repeat(64)
    private val id = "00000000-0000-0000-0000-000000000001"

    @Test
    fun textAndReceiptKeepExistingWireAndSigningFormat() {
        val text = TextWire.text(sender, id, session, "Caffè ☕", "signature")
        val existing = Frame(type = FrameType.TEXT, sender = sender, id = id, session = session, body = text.body, signature = text.signature)
        assertEquals(existing, text)
        assertEquals(text, Wire.decode(Wire.encode(text)))
        assertContentEquals(Wire.signedBytes(existing), Wire.signedBytes(text.copy(signature = "")))
        val ack = TextWire.acknowledgement(sender, id)
        assertEquals(Frame(type = FrameType.ACK, sender = sender, id = id), ack)
        assertEquals(ack, Wire.decode(Wire.encode(ack)))
    }

    @Test
    fun constructorsRejectInvalidIdentifiersAndUtf8Oversize() {
        assertFails { TextWire.text("bad", id, session, "text") }
        assertFails { TextWire.text(sender, "bad", session, "text") }
        assertFails { TextWire.text(sender, id, "bad", "text") }
        assertFails { TextWire.text(sender, id, session, "") }
        assertFails { TextWire.text(sender, id, session, "é".repeat(4097)) }
        assertFails { TextWire.text(sender, id, session, "text", "x".repeat(257)) }
        assertFails { TextWire.acknowledgement("bad", id) }
        assertFails { TextWire.acknowledgement(sender, "bad") }
    }

    @Test
    fun unsignedTextCannotBeDecodedAsAReceivedFrame() {
        val unsigned = TextWire.text(sender, id, session, "text")
        assertFails { Wire.decode(Wire.encode(unsigned)) }
    }
}
