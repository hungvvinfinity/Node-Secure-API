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
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Dual-Tier Key Management for Node-Secure-API Android Client:
 *
 * 1. Tier 1 (Hardware VIP):
 *    - Hardware-backed EC P-256 (secp256r1) key generated in AndroidKeyStore.
 *    - Bound to server attestation challenge.
 *    - StrongBox preferred with TEE fallback.
 *    - Strictly PURPOSE_SIGN.
 *    - Exports X.509 certificate chain (Google Hardware Attestation Root).
 *
 * 2. Tier 2 (Software Protected):
 *    - Standard EC P-256 key pair generated when hardware attestation is unavailable
 *      (e.g., budget chipsets, unlocked bootloaders, devices without Google Play Services).
 *    - Exports standard X.509 SubjectPublicKeyInfo (SPKI) PEM.
 *    - Authenticated via client-side Proof of Work (PoW).
 *
 * Uniform Signing Interface:
 * Both tiers use SHA256withECDSA producing strict DER-encoded ASN.1 SEQUENCE (r, s) base64.
 */
object KeystoreManager {
    const val HARDWARE_KEY_ALIAS = "NodeSecureHardwareKey"
    const val SOFTWARE_KEY_ALIAS = "NodeSecureSoftwareKey"
    private const val PREFS_NAME = "app_secure_prefs"
    private const val KEY_CACHED_HW_LEVEL = "CACHED_HW_SECURITY_LEVEL"
    private const val KEY_ACTIVE_TIER = "ACTIVE_KEY_TIER"

    private val keyStore: KeyStore
        get() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // In-memory software fallback key pair if AndroidKeyStore fails completely
    private var softwareFallbackKeyPair: KeyPair? = null

    // Current active tier: "hardware" or "software"
    var activeTier: String = "hardware"
        get() {
            // Auto-heal if activeTier is default "hardware" but hardware key is absent and software key is present
            if (field == "hardware" && !keyStore.containsAlias(HARDWARE_KEY_ALIAS) &&
                (keyStore.containsAlias(SOFTWARE_KEY_ALIAS) || softwareFallbackKeyPair != null)) {
                return "software"
            }
            return field
        }
        internal set

    // Optional mock signer for unit tests running on local JVM where AndroidKeyStore is unavailable
    internal var testSigner: ((String) -> String)? = null

    /**
     * TIER 1: Generates a hardware-attested EC P-256 key pair bound to the challenge.
     * Tries StrongBox first if supported; falls back to TEE.
     * Throws an exception if device hardware does not support hardware attestation.
     */
    @Synchronized
    fun generateAttestedKeyPair(challengeHex: String, context: Context? = null): KeyPair {
        require(challengeHex.isNotEmpty()) { "Challenge must not be empty" }
        require(challengeHex.length == 64) { "Challenge must be a 64-character hex string" }

        if (keyStore.containsAlias(HARDWARE_KEY_ALIAS)) {
            keyStore.deleteEntry(HARDWARE_KEY_ALIAS)
        }
        if (keyStore.containsAlias(SOFTWARE_KEY_ALIAS)) {
            keyStore.deleteEntry(SOFTWARE_KEY_ALIAS)
        }
        softwareFallbackKeyPair = null

        val hasStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && context != null) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        } else {
            false
        }

        val challengeBytes = challengeHex.toByteArray(Charsets.UTF_8)

        fun createSpec(useStrongBox: Boolean): KeyGenParameterSpec {
            val builder = KeyGenParameterSpec.Builder(
                HARDWARE_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
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

        fun generate(useStrongBox: Boolean): KeyPair {
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(createSpec(useStrongBox))
            return kpg.generateKeyPair()
        }

        val keyPair = if (hasStrongBox) {
            try {
                generate(useStrongBox = true)
            } catch (_: Throwable) {
                generate(useStrongBox = false)
            }
        } else {
            generate(useStrongBox = false)
        }

        activeTier = "hardware"
        context?.applicationContext?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            ?.edit()?.putString(KEY_ACTIVE_TIER, "hardware")?.apply()

        return keyPair
    }

    /**
     * TIER 2: Generates a software EC P-256 key pair without hardware attestation.
     * First attempts creation in AndroidKeyStore (without attestation challenge) so private
     * key remains protected by OS. If that fails, creates standard in-memory EC key.
     */
    @Synchronized
    fun generateSoftwareKeyPair(context: Context? = null): KeyPair {
        if (keyStore.containsAlias(HARDWARE_KEY_ALIAS)) {
            keyStore.deleteEntry(HARDWARE_KEY_ALIAS)
        }
        val keyPair = try {
            if (keyStore.containsAlias(SOFTWARE_KEY_ALIAS)) {
                keyStore.deleteEntry(SOFTWARE_KEY_ALIAS)
            }
            val spec = KeyGenParameterSpec.Builder(
                SOFTWARE_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()

            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            kpg.initialize(spec)
            kpg.generateKeyPair()
        } catch (_: Throwable) {
            // Fallback to standard Java/BouncyCastle EC key generator
            val standardKpg = KeyPairGenerator.getInstance("EC")
            standardKpg.initialize(ECGenParameterSpec("secp256r1"))
            val pair = standardKpg.generateKeyPair()
            softwareFallbackKeyPair = pair
            pair
        }

        activeTier = "software"
        context?.applicationContext?.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            ?.edit()?.putString(KEY_ACTIVE_TIER, "software")?.apply()

        return keyPair
    }

    /**
     * Exports the X.509 certificate chain from leaf to root as DER Base64 strings (Tier 1).
     */
    @Synchronized
    fun getCertificateChainBase64(): List<String> {
        val chain = keyStore.getCertificateChain(HARDWARE_KEY_ALIAS)
            ?: throw IllegalStateException("Missing attestation certificate chain for alias $HARDWARE_KEY_ALIAS")
        return chain.map { cert ->
            Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
        }
    }

    /**
     * Exports a Public Key in standard SPKI PEM format (Tier 2).
     */
    fun exportSpkiPem(publicKey: PublicKey): String {
        val derBytes = publicKey.encoded
        val b64 = Base64.encodeToString(derBytes, Base64.NO_WRAP)
        val wrapped = b64.chunked(64).joinToString("\n")
        return "-----BEGIN PUBLIC KEY-----\n$wrapped\n-----END PUBLIC KEY-----"
    }

    /**
     * Gets the software public key in SPKI PEM format (Tier 2).
     */
    @Synchronized
    fun getSoftwarePublicKeyPem(): String {
        val pubKey: PublicKey = if (keyStore.containsAlias(SOFTWARE_KEY_ALIAS)) {
            val cert = keyStore.getCertificate(SOFTWARE_KEY_ALIAS)
            cert?.publicKey ?: error("Cannot retrieve public key for $SOFTWARE_KEY_ALIAS")
        } else {
            softwareFallbackKeyPair?.public
                ?: error("No software key pair currently available")
        }
        return exportSpkiPem(pubKey)
    }

    /**
     * Signs the canonical UTF-8 string using SHA256withECDSA on the active private key.
     * Uniformly returns standard DER-encoded ASN.1 SEQUENCE (r, s) as canonical Base64.
     */
    @Synchronized
    fun signData(canonicalString: String): String {
        testSigner?.let { return it(canonicalString) }

        val privateKey: PrivateKey = if (activeTier == "hardware") {
            keyStore.getKey(HARDWARE_KEY_ALIAS, null) as? PrivateKey
                ?: throw IllegalStateException("Hardware private key not found ($HARDWARE_KEY_ALIAS)")
        } else {
            if (keyStore.containsAlias(SOFTWARE_KEY_ALIAS)) {
                keyStore.getKey(SOFTWARE_KEY_ALIAS, null) as? PrivateKey
                    ?: softwareFallbackKeyPair?.private
                    ?: throw IllegalStateException("Software private key not found ($SOFTWARE_KEY_ALIAS)")
            } else {
                softwareFallbackKeyPair?.private
                    ?: throw IllegalStateException("Software private key not found")
            }
        }

        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(canonicalString.toByteArray(Charsets.UTF_8))
        val derBytes = signer.sign()

        return Base64.encodeToString(derBytes, Base64.NO_WRAP)
    }

    /**
     * Checks if the device key exists for the active tier.
     */
    @Synchronized
    fun isDeviceKeyReady(): Boolean {
        return if (activeTier == "hardware") {
            keyStore.containsAlias(HARDWARE_KEY_ALIAS)
        } else {
            keyStore.containsAlias(SOFTWARE_KEY_ALIAS) || softwareFallbackKeyPair != null
        }
    }

    /**
     * Deletes all local keys (both hardware and software).
     */
    @Synchronized
    fun deleteKey() {
        if (keyStore.containsAlias(HARDWARE_KEY_ALIAS)) {
            keyStore.deleteEntry(HARDWARE_KEY_ALIAS)
        }
        if (keyStore.containsAlias(SOFTWARE_KEY_ALIAS)) {
            keyStore.deleteEntry(SOFTWARE_KEY_ALIAS)
        }
        softwareFallbackKeyPair = null
        activeTier = "hardware"
    }

    /**
     * Detects hardware security level: StrongBox, TEE, or Software.
     */
    @Synchronized
    fun getOrDetectHardwareSecurityLevel(context: Context): String {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        if (keyStore.containsAlias(HARDWARE_KEY_ALIAS)) {
            try {
                val privateKey = keyStore.getKey(HARDWARE_KEY_ALIAS, null) as? PrivateKey
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
            } catch (_: Throwable) {}
        }

        val cached = prefs.getString(KEY_CACHED_HW_LEVEL, null)
        if (!cached.isNullOrEmpty()) return cached

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
