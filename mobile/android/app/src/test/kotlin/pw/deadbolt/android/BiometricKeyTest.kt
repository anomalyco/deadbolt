package pw.deadbolt.android

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The token format and freshness rule, with a JVM AES key standing in for the Keystore one. */
class BiometricKeyTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val wrapping = ByteArray(32) { it.toByte() }

    private fun token(createdAt: Long): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        return BiometricKey.seal(BiometricKey.NewKey("deadbolt-biometric-test", createdAt, cipher), cipher, wrapping)
    }

    private fun open(token: ByteArray): ByteArray {
        val envelope = requireNotNull(BiometricKey.parse(token))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.iv))
        }
        return BiometricKey.open(cipher, envelope)
    }

    @Test
    fun aTokenOpensToItsWrappingKey() {
        val t = token(1_800_000_000)
        val envelope = BiometricKey.parse(t)!!
        assertEquals(1_800_000_000, envelope.createdAt)
        assertEquals("deadbolt-biometric-test", envelope.alias)
        assertArrayEquals(wrapping, open(t))
    }

    @Test(expected = AEADBadTagException::class)
    fun theEnrollmentTimeCannotBeMovedForward() {
        val t = token(1_800_000_000)
        t[12] = (t[12] + 1).toByte() // last byte of created_at
        open(t)
    }

    @Test
    fun malformedOrOldTokensAreNotOurs() {
        assertNull(BiometricKey.parse(ByteArray(0)))
        val t = token(1)
        assertNull(BiometricKey.parse(t.copyOf(t.size - 1)))
        assertNull(BiometricKey.parse(t + byteArrayOf(0)))
        assertNull(BiometricKey.parse(t.copyOf().also { it[4] = 1 })) // version 1
    }

    @Test
    fun fingerprintUnlockLastsFourteenDays() {
        val at = 1_800_000_000L
        assertTrue(BiometricKey.fresh(at, at))
        assertTrue(BiometricKey.fresh(at, at + BiometricKey.MAX_AGE_SECONDS))
        assertFalse(BiometricKey.fresh(at, at + BiometricKey.MAX_AGE_SECONDS + 1))
        assertFalse("a clock set back before enrollment ends it", BiometricKey.fresh(at, at - 1))
        assertFalse("a forged negative time can't wrap around", BiometricKey.fresh(Long.MIN_VALUE, at))
    }
}
