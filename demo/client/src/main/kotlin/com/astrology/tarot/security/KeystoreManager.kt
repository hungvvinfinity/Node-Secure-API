package com.astrology.tarot.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Manages hardware-backed EC P-256 (secp256r1) key pairs in AndroidKeyStore.
 *
 * Implements Android Key Attestation requirements:
 * - Real hardware keystore (StrongBox preferred with TEE fallback).
 * - Attestation challenge set to UTF-8 bytes of the 64-character server challenge hex string.
 * - Key purpose: strictly PURPOSE_SIGN (asymmetric private key used exclusively for signing).
 * - Non-interactive API protection: userAuthenticationRequired is disabled (false) to prevent
 *   session invalidation on lock-screen credential changes.
 * - Strict DER-encoded ECDSA signatures (r, s sequence) base64 without wrapping.
 */
object KeystoreManager {
    const val KEY_ALIAS = "NodeSecureHardwareKey"
    private const val PREFS_NAME = "app_secure_prefs"
    private const val KEY_CACHED_HW_LEVEL = "CACHED_HW_SECURITY_LEVEL"

    private val keyStore: KeyStore
        get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /**
     * Generates a new EC P-256 key pair bound to the server attestation challenge.
     * Tries StrongBox first if supported by hardware; gracefully falls back to TEE.
     * Uses strictly PURPOSE_SIGN for the private signing key.
     */
    @Synchronized
    fun generateAttestedKeyPair(challengeHex: String, context: Context? = null): KeyPair {
        require(challengeHex.isNotEmpty()) { "Challenge must not be empty" }
        require(challengeHex.length == 64) { "Challenge must be a 64-character hex string" }

        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }

        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context != null) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }

        // Protocol requirement: challenge bytes for AndroidKeyStore setAttestationChallenge
        // MUST BE the UTF-8 bytes of the hex string, NOT hex-decoded bytes.
        val challengeBytes = challengeHex.toByteArray(Charsets.UTF_8)

        fun createSpec(useStrongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN // Strictly PURPOSE_SIGN per security review
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challengeBytes)
                .setUserAuthenticationRequired(false)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(useStrongBox)
            }
            return builder.build()
        }

        fun generateWithSpec(useStrongBox: Boolean): KeyPair {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(createSpec(useStrongBox))
            return kpg.generateKeyPair()
        }

        return if (hasStrongBox) {
            try {
                generateWithSpec(useStrongBox = true)
            } catch (_: Throwable) {
                // StrongBox failed or unavailable, fallback to TEE
                generateWithSpec(useStrongBox = false)
            }
        } else {
            generateWithSpec(useStrongBox = false)
        }
    }

    /**
     * Exports the X.509 certificate chain from leaf to root as a list of DER Base64 strings.
     */
    @Synchronized
    fun getCertificateChainBase64(): List<String> {
        val chain = keyStore.getCertificateChain(KEY_ALIAS)
            ?: throw IllegalStateException("Missing attestation certificate chain for alias $KEY_ALIAS")
        return chain.map { cert ->
            Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
        }
    }

    // Optional mock signer for unit tests running on local JVM where AndroidKeyStore is unavailable
    internal var testSigner: ((String) -> String)? = null

    /**
     * Signs the canonical UTF-8 string with the hardware private key using SHA256withECDSA.
     * Returns standard DER-encoded ASN.1 SEQUENCE (r, s) as canonical Base64 (no wrap).
     */
    @Synchronized
    fun signData(canonicalString: String): String {
        testSigner?.let { return it(canonicalString) }

        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("Private key not found for alias $KEY_ALIAS")

        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(canonicalString.toByteArray(Charsets.UTF_8))
        val derBytes = signer.sign()

        return Base64.encodeToString(derBytes, Base64.NO_WRAP)
    }

    /**
     * Checks if the device key exists in AndroidKeyStore.
     */
    @Synchronized
    fun isDeviceKeyReady(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    /**
     * Deletes the device key from AndroidKeyStore.
     */
    @Synchronized
    fun deleteKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    /**
     * Detects hardware security level: StrongBox, TEE, or Software.
     * Prioritizes directly querying KeyInfo of the real KEY_ALIAS if it already exists,
     * then checks cache, then falls back to probing.
     */
    @Synchronized
    fun getOrDetectHardwareSecurityLevel(context: Context): String {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // 1. If real key KEY_ALIAS exists, directly inspect its hardware KeyInfo
        if (keyStore.containsAlias(KEY_ALIAS)) {
            try {
                val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
                if (privateKey != null) {
                    val factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
                    val level = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        when (keyInfo.securityLevel) {
                            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                            else -> "Software"
                        }
                    } else {
                        @Suppress("DEPRECATION")
                        if (keyInfo.isInsideSecureHardware) "TEE" else "Software"
                    }
                    prefs.edit().putString(KEY_CACHED_HW_LEVEL, level).apply()
                    return level
                }
            } catch (_: Throwable) {
                // If KeyInfo query on existing key fails, continue to fallback detection
            }
        }

        // 2. Check cached hardware level
        val cached = prefs.getString(KEY_CACHED_HW_LEVEL, null)
        if (!cached.isNullOrEmpty()) return cached

        // 3. Probing fallback
        val detected = try {
            val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            } else false

            if (hasStrongBox) {
                "StrongBox"
            } else {
                val probeAlias = "_probe_hw_sec"
                try {
                    if (keyStore.containsAlias(probeAlias)) keyStore.deleteEntry(probeAlias)
                    val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    kpg.initialize(
                        KeyGenParameterSpec.Builder(probeAlias, KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .build()
                    )
                    val kp = kpg.generateKeyPair()
                    val factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    val keyInfo = factory.getKeySpec(kp.private, KeyInfo::class.java)
                    val level = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        when (keyInfo.securityLevel) {
                            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                            else -> "Software"
                        }
                    } else {
                        @Suppress("DEPRECATION")
                        if (keyInfo.isInsideSecureHardware) "TEE" else "Software"
                    }
                    keyStore.deleteEntry(probeAlias)
                    level
                } catch (_: Throwable) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                        context.packageManager.hasSystemFeature("android.hardware.hardware_keystore")) {
                        "TEE"
                    } else {
                        "Software"
                    }
                }
            }
        } catch (_: Throwable) {
            "Software"
        }

        prefs.edit().putString(KEY_CACHED_HW_LEVEL, detected).commit()
        return detected
    }
}
