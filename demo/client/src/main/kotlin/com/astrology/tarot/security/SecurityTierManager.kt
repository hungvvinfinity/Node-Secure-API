package com.astrology.tarot.security

import android.content.Context

enum class DeviceSecurityTier {
    TIER_1_ZERO_CLICK,
    TIER_2_REQUIRE_REGISTRATION
}

object SecurityTierManager {
    private const val PREFS_NAME = "app_secure_prefs"
    private const val KEY_REGISTERED = "registered"

    fun determineSecurityTier(context: Context): DeviceSecurityTier = try {
        val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val registered = prefs.getBoolean(KEY_REGISTERED, false)
        if (registered && KeystoreManager.isDeviceKeyReady()) {
            DeviceSecurityTier.TIER_1_ZERO_CLICK
        } else {
            DeviceSecurityTier.TIER_2_REQUIRE_REGISTRATION
        }
    } catch (_: Exception) {
        DeviceSecurityTier.TIER_2_REQUIRE_REGISTRATION
    }
}
