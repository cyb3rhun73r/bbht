# Mobile App / API — Real Disclosed-Report Pattern Library

Many programs include mobile apps (Android/iOS) in scope, and they're
consistently under-tested relative to the web app — most hunters default
to the website and skip the APK/IPA sitting right there in the scope.
Drawn from disclosed HackerOne reports.

## Where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Hardcoded credentials/URL in the app binary** | 8x8 (H1 #412772) | The Android app shipped with a hardcoded URL containing credentials for a third-party bug-capture API — found simply by decompiling the APK and grepping strings, no dynamic testing needed. |
| **Hardcoded API secret enabling unauthorized uploads** | Reverb.com Android app | A hardcoded Cloudinary API secret in the APK allowed unauthorized file uploads to the app's cloud storage — same "grep the decompiled strings" discovery method. |
| **Third-party API credentials leaked in APK** | GlassWire | Facebook App API credentials found in the decompiled APK. |
| **Hardcoded keys in GitHub repos tied to mobile apps** | Rocket.Chat (H1 #766346), X/xAI AppLovin key (H1 #674774) | Same info-disclosure pattern as the web case (see `info-disclosure-patterns.md`) but the source was a mobile SDK integration's config, committed to a public repo. |
| **Deep link hijacking** | General pattern, multiple programs | Mobile apps register custom URL schemes (`myapp://...`) or Android App Links / iOS Universal Links to handle actions like password reset or login. If the app doesn't validate the deep link's parameters or origin, another app (or a malicious webpage) can trigger privileged in-app actions — these are rated higher than web equivalents because they can lead to account takeover on the physical device. |
| **Insecure local storage** | General pattern | Sensitive data (session tokens, PII, cached API responses) stored unencrypted in the app's local SQLite DB, SharedPreferences (Android), or plist/UserDefaults (iOS) — recoverable by anyone with physical/backup access to the device, or via a rooted/jailbroken device. |

## Fast test approach

### Static analysis (no device needed — fastest starting point)
1. **Get the APK**: download directly if the app is on the Play Store
   (via `apkeep`/`apkpure`-style tools, or pull from a test device with
   `adb pull`), or extract an `.ipa` if targeting iOS.
2. **Decompile**: `apktool d app.apk` (Android) or `jadx -d output app.apk`
   for readable Java-like source. For iOS, `class-dump` or inspecting the
   binary with `otool`/`nm` for strings.
3. **Grep for secrets** — same patterns as `info-disclosure-patterns.md`:
   ```
   api[_-]?key, secret, token, password, Authorization,
   AKIA (AWS), -----BEGIN (private keys), firebase, cloudinary,
   https?://[^/]*:[^/]*@   (credentials embedded in a URL)
   ```
   `trufflehog filesystem <decompiled-dir>` automates this well.
4. **Check `AndroidManifest.xml`** (Android) for:
   - `android:debuggable="true"` left enabled in a production build
   - Exported activities/services/receivers (`android:exported="true"`)
     that shouldn't be reachable by other apps
   - Registered custom URL schemes / intent filters (deep links) — note
     every one for the dynamic testing pass below
5. **Check for hardcoded internal/staging URLs** — decompiled strings
   often reveal internal API endpoints, staging environments, or debug
   panels not linked from the production app UI.

### Dynamic analysis (needs an emulator/device + proxy)
6. **Proxy the app's traffic** through Burp/mitmproxy (install the proxy
   CA cert on the device/emulator; for apps with certificate pinning,
   use Frida with an unpinning script — `objection` wraps this well).
7. **Compare the mobile API surface to the web API** — mobile apps often
   talk to a separate or older API version with weaker authz/validation
   (per the recurring "mobile API lags behind web fixes" pattern noted
   in `idor-bola-patterns.md`). Run the same IDOR/access-control tests
   from that file against every endpoint the mobile app calls.
8. **Test deep links**: for each registered scheme/intent filter found in
   the manifest, try triggering it from `adb shell am start -W -a
   android.intent.action.VIEW -d "myapp://action?param=value"` (Android)
   or from a test webpage/Notes app link (iOS) — check whether sensitive
   actions (login, password change, adding a payment method) can be
   triggered without the app's normal in-app authorization checks, or
   whether a malicious app/page can intercept a link meant for the
   legitimate app.
9. **Check local storage** after using the app normally: pull the app's
   data directory (`adb shell run-as <package> ...` or via a rooted
   device) and inspect SQLite DBs, SharedPreferences XML, and any cache
   files for tokens/PII stored in plaintext.

## Tools
- `apktool`, `jadx` — Android decompilation
- `mitmproxy` / Burp Suite — traffic interception
- `objection` / Frida — SSL pinning bypass, runtime instrumentation
- `mob-fs` (MobSF) — automated static + dynamic analysis, good first pass
  before manual review
- `trufflehog` / `gitleaks` — secrets scanning on decompiled source

## Why this pays disproportionately well
Many programs have a large web-testing population and a much smaller
mobile-testing population, simply because decompiling and proxying a
mobile app has a higher setup cost than opening Burp on a website. That
setup cost is exactly why it's worth doing — less competition on the same
scope, for bugs that are often rated *higher* severity than their web
equivalent because of the account-takeover/device-level impact deep link
and local-storage issues can have.
