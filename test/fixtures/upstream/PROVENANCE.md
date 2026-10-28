# Upstream Test Fixture Provenance

The fixtures in this directory are vendored from the official Android Key Attestation repository:
- **Repository**: https://github.com/android/keyattestation
- **Upstream Commit**: `34652d3df68b8d6887a6670b00eb0856090dae6d` (2026-10-26)
- **License**: Apache License 2.0 (see `LICENSE` in this directory)
- **Date Retrieved**: 2026-10-28

## Vendored Fixtures:
1. `caiman/sdk36/TEE_EC_RKP.{pem,json}`:
   - Device: Google Pixel 9 Pro (`caiman`)
   - Platform: Android 16 (SDK 36)
   - Attestation: TEE EC P-256 via Remotely Provisioned Key (RKP)
   - Trust Root: Exercises reissued 2019 RSA Root vs 2022 pin (same SPKI)
   - Expected valid timestamp: `2025-09-26` (1758900680964)
   - Expected expired at current time: `2026-10-28`
2. `tegu/sdk36/TEE_EC_2026_ROOT.{pem,json}`:
   - Device: Pre-production Google Pixel 9a (`tegu`)
   - Platform: Android 16 (SDK 36)
   - Attestation: TEE EC P-256 signed by new 2026 EC Root CA
   - Trust Root: Official Google Hardware Attestation Root 2 (EC P-384)
   - Expected valid timestamp: `2026-02-25` (1771894563060)

## Notice
These fixtures are used solely for offline cryptographic interoperability verification against official Google root certificates and AOSP schema. They do not constitute live device credentials.
