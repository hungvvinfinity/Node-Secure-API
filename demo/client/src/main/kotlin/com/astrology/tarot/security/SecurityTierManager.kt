package com.astrology.tarot.security

import android.content.Context

enum class DeviceSecurityTier(val displayName: String) {
    TIER_1_HARDWARE("Tier 1: Hardware VIP (0ms Delay, Permanent)"),
    TIER_2_SOFTWARE("Tier 2: Software Protected (3.0s Tarpit, 2h Lease)"),
    UNREGISTERED("Chưa đăng ký (Unregistered)")
}

object SecurityTierManager {
    private const val PREFS_NAME = "app_secure_prefs"
    private const val KEY_REGISTERED = "registered"
    private const val KEY_TIER = "device_tier"
    private const val KEY_EXPIRES_AT = "lease_expires_at"

    fun determineSecurityTier(context: Context): DeviceSecurityTier = try {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val registered = prefs.getBoolean(KEY_REGISTERED, false)

        if (!registered || !KeystoreManager.isDeviceKeyReady()) {
            DeviceSecurityTier.UNREGISTERED
        } else {
            val tier = prefs.getString(KEY_TIER, "hardware")
            if (tier == "software") {
                val expiresAt = prefs.getLong(KEY_EXPIRES_AT, 0L)
                if (expiresAt > 0 && System.currentTimeMillis() >= expiresAt) {
                    DeviceSecurityTier.UNREGISTERED // Expired
                } else {
                    DeviceSecurityTier.TIER_2_SOFTWARE
                }
            } else {
                DeviceSecurityTier.TIER_1_HARDWARE
            }
        }
    } catch (_: Exception) {
        DeviceSecurityTier.UNREGISTERED
    }

    /**
     * Checks if a software tier lease is expired or close to expiring (within 5 minutes).
     */
    fun isLeaseExpiringSoon(context: Context, bufferMinutes: Long = 5): Boolean {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val tier = prefs.getString(KEY_TIER, null) ?: return true
        if (tier != "software") return false // Hardware tier is permanent

        val expiresAt = prefs.getLong(KEY_EXPIRES_AT, 0L)
        if (expiresAt <= 0L) return true

        val threshold = expiresAt - (bufferMinutes * 60 * 1000L)
        return System.currentTimeMillis() >= threshold
    }

    /**
     * Gets remaining lease duration in minutes (returns -1 for hardware/permanent).
     */
    fun getLeaseRemainingMinutes(context: Context): Long {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val tier = prefs.getString(KEY_TIER, null) ?: return 0
        if (tier == "hardware") return -1L

        val expiresAt = prefs.getLong(KEY_EXPIRES_AT, 0L)
        val diff = expiresAt - System.currentTimeMillis()
        return if (diff > 0) diff / (60 * 1000L) else 0L
    }
}
