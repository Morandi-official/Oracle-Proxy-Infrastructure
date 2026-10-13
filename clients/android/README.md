# Oracle Proxy Android — alpha (A0)

The alpha sources use the **official WireGuard tunnel AAR** from Maven Central
(`com.wireguard.android:tunnel:1.0.20260102`, Apache-2.0) instead of
reimplementing VPN cryptography. See the upstream library license and its
transitive notices before redistribution.

## Functionality implemented

- Native Android application with an on-device local WireGuard `.conf` import
  using Android's system file picker.
- Imports are constrained to 32 KiB, parsed with the official WireGuard library,
  and held in app memory only (no repository secrets, no saved plaintext configs,
  no backups, no network uploads).
- Conservative configuration preflight: **exactly one peer**, interface Address,
  DNS, both IPv4 and IPv6 full-tunnel default routes, and peer Endpoint.
- Android's **system VPN consent dialog** is required before invoking
  `GoBackend.setState(..., UP, config)` on a background worker.
- Explicit disconnect invokes `GoBackend.setState(..., DOWN, null)`.
- UI never treats an UP state as a verified handshake or proof of a kill switch.
- No per-app bypass/exclusion is accepted in this alpha.

## Build

Android SDK 35, JDK 17, Gradle 8.11.1, Android Gradle Plugin 8.8.2.
From `clients/android` on a development machine with the SDK available:

```shell
gradle :app:testDebugUnitTest
gradle :app:assembleDebug
```

GitHub Actions workflow `Android WireGuard alpha build` builds a **debug APK**
as `oracle-proxy-android-alpha-debug-apk`. This is not a store-ready
release, no production signing or independent security audit has taken place.
Only deploy to an isolated test Android device after reviewing source. No
administrator/root access is needed.

## Critical limitations

**This is the first attempt at a real tunnel path, NOT a certified secure VPN.**
Successful APK compilation does not prove it can handshake with Oracle or
successfully enforce IPv4/IPv6/DNS routing on an actual Android device.

- The app does not start its own permanent foreground service or restore
  tunnel config after process death. Backend-managed VpnService integration
  requires device testing across Android releases.
- No trustworthy packet-leak, VPN failure, system reboot, Doze, Always-On,
  or Android lockdown testing has occurred. Android lockdown can conflict
  with package exclusions, which must be validated on a device.
- The key/config is intentionally not persisted; after app process death
  reimport is required. Do not use this alpha as unattended protection.
- No auto-switch to UDP 443 or account provisioning. The imported config must
  already use the tested Oracle endpoint and a safe DNS, and must be created
  for a **separate Android peer**. Never reuse your Windows client private key.
- Never commit/share a real imported `.conf` or private key, including in issue
  reports or screenshots.
- The APK is a **GitHub CI-generated debug build**. Do not bypass Android
  security warnings to install unknown software. Manual testing is a separate
  authorization gate.

## Important project boundary

The UU remote desktop at the second Windows PC is not modified by this
Android project. Avoid experimenting with that PC's active WireSock session.
