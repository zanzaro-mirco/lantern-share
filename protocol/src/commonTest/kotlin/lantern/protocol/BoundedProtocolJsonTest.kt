package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BoundedProtocolJsonTest {
    @Test
    fun depthCountsContainersButNotQuotedOrEscapedCharacters() {
        val vectors = listOf(
            """{"x":"[[[{{{}}}]]]"}""",
            """{"x":"\"[[[","y":[]}""",
            """{"x":"\\","y":[]}""",
            """{"x":"\\\"[[[","y":[]}""",
            """{"x":"\u005b\u007b","y":[]}""",
        )
        for (vector in vectors) {
            assertEquals(vector, decodeBoundedProtocolJson(vector.encodeToByteArray(), 4096, maxDepth = 2))
        }
    }

    @Test
    fun nestedContainersAndNegativeDepthFailBeforeParsing() {
        for (vector in listOf("[[[]]]", "{\"x\":[{}]}", "]", "{}]")) {
            assertFailsWith<IllegalArgumentException> {
                decodeBoundedProtocolJson(vector.encodeToByteArray(), 4096, maxDepth = 2)
            }
        }
    }
}
