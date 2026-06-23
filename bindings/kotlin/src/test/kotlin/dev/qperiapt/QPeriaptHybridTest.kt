package dev.qperiapt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Cross-platform consistency: decapsulate the shared Rust-generated vector and
 * assert the secret matches byte-for-byte (bindings/shared-test-vectors.json).
 */
class QPeriaptHybridTest {
    private fun hex(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte()
    }

    // Minimal field extraction (the vector is a flat object of "key":"hex").
    private fun field(json: String, key: String): String =
        Regex("\"$key\"\\s*:\\s*\"([0-9a-f]*)\"").find(json)!!.groupValues[1]

    @Test
    fun sharedVectorDecapsulates() {
        val json = File("../shared-test-vectors.json").readText()
        val secret = QPeriaptHybrid.decapsulate(
            profile = QPeriaptHybrid.PROFILE_CONTEXT_BOUND,
            suiteId = hex(field(json, "suite_id")),
            policyVersion = 1,
            skPq = hex(field(json, "sk_pq")),
            ctPq = hex(field(json, "ct_pq")),
            pkPq = hex(field(json, "pk_pq")),
            skTrad = hex(field(json, "sk_trad")),
            ctTrad = hex(field(json, "ct_trad")),
            pkTrad = hex(field(json, "pk_trad")),
            context = hex(field(json, "context")),
        )
        assertContentEquals(hex(field(json, "secret")), secret,
            "Kotlin decapsulation must match the Rust core byte-for-byte")
    }

    /** Cross-platform combiner reference vectors: feed each `input` blob to the C ABI
     * `combine` and assert the 32-byte key (bindings/contextbound-vectors.txt). */
    @Test
    fun combineReferenceVectors() {
        val text = File("../contextbound-vectors.txt").readText()
        var n = 0
        for (line in text.lines()) {
            val p = line.trim().split(" ")
            if (p.size != 3) continue
            val got = QPeriaptHybrid.combine(p[0].toByte(), hex(p[1]))
            assertContentEquals(hex(p[2]), got,
                "Kotlin combine must match the Rust core byte-for-byte")
            n++
        }
        assertEquals(6, n, "expected 6 reference vectors")
    }
}
