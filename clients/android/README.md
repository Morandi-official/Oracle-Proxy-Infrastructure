# Proxy for Android

Proxy for Android uses Android's VPN consent and the official WireGuard Android tunnel library. The APK supports Android 10 (API 29) or later. The interface uses the Android system font, grouped controls, light and dark palettes, and a single prominent connection action.

## First connection

1. Install the signed `Proxy-Android.apk` from the repository's Android release.
2. Sign in with the proxy account assigned by the administrator. Confirm the device name and register the device when prompted.
3. Tap **连接** and approve Android's VPN permission. Keep Proxy in the foreground until it finishes the first exit check.
4. Use **账号与设备** to check the current 30-day quota period, account expiry, and registered devices. Use **诊断** to view the active endpoint and verified exit addresses.

The app starts with the preferred entrance authorized by the account. It tries the server-advertised UDP ports and an authorized backup when available. The port selector changes the first port attempted. The app uses HTTPS for the existing account control API, including enrollment and revocation. The device creates and retains its WireGuard key locally. Android Keystore protects the key and any remembered access token. The app does not save the account password.

The WireGuard release can install over the previously signed Proxy app. The WireGuard and Tailscale clients use separate session and device stores. Sign in with your proxy account if the WireGuard client has no remembered session. Android may ask for VPN permission again because the tunnel service changed.

Proxy shows a connection only after WireGuard has authenticated and the tunnel has verified the expected IPv4 exit, plus the expected IPv6 exit when the server enables IPv6. When IPv6 is disabled by policy, the VPN blocks it while connected. The browser and other apps use the Android VPN when it is active. Android can resume direct connections between tunnel attempts and after disconnection. This version does not provide Android Always-on VPN or a kill switch.

If a network handover interrupts exit verification, Proxy closes the unsuccessful connection and offers another connection attempt. The VPN notification has a **断开** action. On Android 13 or later, the system notification is visible in the notification shade when notification permission is granted.

## Build and test

Use JDK 17, Gradle 8.13, Android SDK Platform 36 and Android Build Tools 36.0.0.

```sh
cd clients/android
gradle --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest :app:testDebugUnitTest :app:lintDebug
```

The GitHub Android workflow then installs the app and its instrumentation APK on API 29 and 36. It exercises device enrollment and the real Android VPN permission flow, then verifies bidirectional traffic with an isolated Linux WireGuard peer. The test fixtures use ephemeral identities in the runner and do not require an administrator password.

## Sign and publish

Create or reuse an owner-controlled Android signing keystore. Keep the same signing key for updates to `org.morandi.proxy`. The `android-release` GitHub Environment supplies these secrets for release builds:

| Secret | Value |
| --- | --- |
| `ANDROID_SIGNING_KEYSTORE_B64` | Base64-encoded keystore |
| `ANDROID_SIGNING_KEYSTORE_PASSWORD` | Keystore password |
| `ANDROID_SIGNING_KEY_ALIAS` | Signing key alias |
| `ANDROID_SIGNING_KEY_PASSWORD` | Signing key password |

Keep a secure offline copy of the keystore. Restrict the release environment to the default branch. When an Android version change with a higher version code lands on `main`, the workflow builds the signed candidate. You can also open **Actions → Android client build and acceptance → Run workflow** on `main` and enable **Publish a signed APK after Android acceptance**. Publication requires the same signed APK to install over the previous signed Android package and pass WireGuard tests on both emulator API levels. A separate job uses the existing dedicated acceptance account in `windows-client-acceptance` to check real account TLS, WireGuard, DNS and verified exit from a fresh installation. It removes only the device it enrolled. New WireGuard Android releases use `wireguard-android-v<version>` tags.

## References

- [Android VPN developer guide](https://developer.android.com/develop/connectivity/vpn)
- [WireGuard embedding for Android](https://www.wireguard.com/embedding/)
- [Apple HIG designing for iOS](https://developer.apple.com/design/human-interface-guidelines/designing-for-ios)
- [Apple HIG accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility)
