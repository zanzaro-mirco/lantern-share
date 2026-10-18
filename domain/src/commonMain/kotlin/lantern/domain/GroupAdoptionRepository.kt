package lantern.domain

/**
 * Durable local adoption, distinct from its untrusted pending journal and PoC peer trust.
 * A trusted serial owner must hold live consent and serialize identity/lifecycle changes
 * with commit. No network, crypto, UI or lifecycle callbacks inside repository operations.
 */
interface GroupAdoptionRepository : LocalGroupRepository, GroupAdoptionJournalRepository {
    /** Durable marker plus full material; verify identity and historical signatures before reuse. */
    fun committedGroupAdoption(): PendingGroupAdoption?

    /**
     * Atomically promote the EXACT staged record if no group exists, then remove its journal.
     * True inserted; false exact already-committed retry. Mismatch, absent stage, changed
     * identity or another group throws without overwriting. Does not itself check consent.
     * An exception is not proof of rollback: reread the durable result, never blindly replay.
     */
    fun commitGroupAdoption(record: PendingGroupAdoption, currentIdentityId: String): Boolean
}
