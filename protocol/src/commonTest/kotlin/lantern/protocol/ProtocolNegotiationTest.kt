package lantern.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ProtocolNegotiationTest {
    @Test
    fun selectsOnlyCommonFeaturesInDeterministicOrder() {
        val local = capabilities(setOf("text", "receipts", "future-feature"), setOf("text"))
        val remote = capabilities(setOf("receipts", "text", "other-feature"), setOf("receipts"))
        val result = ProtocolNegotiation.negotiate(local, remote)
        assertEquals(ProtocolNegotiationResult.Compatible(1, setOf("receipts", "text")), result)
        assertEquals(result, ProtocolNegotiation.negotiate(remote, local))
        assertEquals(listOf("receipts", "text"), (result as ProtocolNegotiationResult.Compatible).features.toList())
    }

    @Test
    fun rejectsRequiredFeatureMissingOnEitherSide() {
        val demanding = capabilities(setOf("text", "receipts"), setOf("receipts"))
        val basic = capabilities(setOf("text"))
        val expected = ProtocolNegotiationResult.Incompatible(ProtocolIncompatibility.REQUIRED_FEATURE_MISSING)
        assertEquals(expected, ProtocolNegotiation.negotiate(demanding, basic))
        assertEquals(expected, ProtocolNegotiation.negotiate(basic, demanding))
    }

    @Test
    fun optionalUnknownFeaturesDoNotPreventCompatibility() {
        assertEquals(
            ProtocolNegotiationResult.Compatible(1, emptySet()),
            ProtocolNegotiation.negotiate(capabilities(setOf("future-feature")), capabilities(emptySet())),
        )
    }

    @Test
    fun rejectsFutureVersionsEvenWhenBothSidesOfferThem() {
        val current = capabilities(setOf("text"))
        val future = ProtocolCapabilities(2, setOf("text"))
        val expected = ProtocolNegotiationResult.Incompatible(ProtocolIncompatibility.UNSUPPORTED_VERSION)
        assertEquals(expected, ProtocolNegotiation.negotiate(current, future))
        assertEquals(expected, ProtocolNegotiation.negotiate(future, current))
        assertEquals(expected, ProtocolNegotiation.negotiate(future, future))
    }

    @Test
    fun invalidOffersAreRejectedBeforeNegotiation() {
        for (version in listOf(-1, 0, 256)) {
            assertFailsWith<IllegalArgumentException> { ProtocolCapabilities(version, emptySet()) }
        }
        for (feature in listOf("", "TEXT", "with space", "é", "a".repeat(33))) {
            assertFailsWith<IllegalArgumentException> { capabilities(setOf(feature)) }
        }
        assertFailsWith<IllegalArgumentException> { capabilities(setOf("text"), setOf("receipts")) }
        assertFailsWith<IllegalArgumentException> { capabilities((1..33).map { "feature-$it" }.toSet()) }
        capabilities((1..32).map { "feature-$it" }.toSet())
        capabilities(setOf("a".repeat(32)))
    }

    @Test
    fun capabilitiesKeepSnapshotOfCallerOwnedCollections() {
        val supported = mutableSetOf("text")
        val required = mutableSetOf("text")
        val offer = capabilities(supported, required)
        supported.clear()
        required.add("receipts")
        assertEquals(setOf("text"), offer.supportedFeatures)
        assertEquals(setOf("text"), offer.requiredFeatures)
        assertEquals(
            ProtocolNegotiationResult.Compatible(1, setOf("text")),
            ProtocolNegotiation.negotiate(offer, capabilities(setOf("text"))),
        )
    }

    private fun capabilities(supported: Set<String>, required: Set<String> = emptySet()) =
        ProtocolCapabilities(ProtocolNegotiation.VERSION, supported, required)
}
