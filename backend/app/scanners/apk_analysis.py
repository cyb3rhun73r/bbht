"""Static analysis of Android APKs for common Mobile OWASP Top 10 issues.

Pure static analysis (manifest inspection + string/byte scanning of the APK
archive) - no dynamic instrumentation, no code execution, no decompilation
beyond what androguard needs to read the manifest. Safe to run on any APK
you're authorized to test (your own app builds, or in-scope mobile targets
of a bug bounty program).
"""
import re
import zipfile

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "high",
    "android.permission.RECEIVE_SMS": "high",
    "android.permission.SEND_SMS": "high",
    "android.permission.READ_CALL_LOG": "high",
    "android.permission.WRITE_CALL_LOG": "high",
    "android.permission.PROCESS_OUTGOING_CALLS": "high",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "high",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "high",
    "android.permission.REQUEST_INSTALL_PACKAGES": "high",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "high",
    "android.permission.BIND_DEVICE_ADMIN": "high",
    "android.permission.SYSTEM_ALERT_WINDOW": "medium",
    "android.permission.ACCESS_FINE_LOCATION": "medium",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.WRITE_CONTACTS": "medium",
    "android.permission.CAMERA": "medium",
    "android.permission.RECORD_AUDIO": "medium",
    "android.permission.READ_PHONE_STATE": "medium",
    "android.permission.WRITE_EXTERNAL_STORAGE": "low",
}

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(rb"AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase Database URL", re.compile(rb"https://[a-zA-Z0-9-]+\.firebaseio\.com")),
    ("Stripe Live Secret Key", re.compile(rb"sk_live_[0-9a-zA-Z]{20,}")),
    ("Slack Token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Private Key Material", re.compile(rb"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic API Key/Secret Assignment", re.compile(
        rb'(?i)(api[_-]?key|secret|access[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{12,}'
    )),
]

SCANNABLE_EXT = (".xml", ".dex", ".json", ".txt", ".properties", ".arsc", "")
MAX_FILE_BYTES = 15 * 1024 * 1024  # skip huge files (native libs, media) for perf
MAX_MATCHES_PER_PATTERN = 5


def _attr(elem, name, default=None):
    return elem.get(ANDROID_NS + name, default)


def _component_findings(app_elem, tag, kind, emit, target_sdk):
    app_level_perm = _attr(app_elem, "permission")
    for comp in app_elem.findall(tag):
        name = _attr(comp, "name", "?")
        exported_attr = _attr(comp, "exported")
        has_intent_filter = comp.find("intent-filter") is not None
        if exported_attr is not None:
            exported = exported_attr.lower() == "true"
        else:
            # Pre-Android 12 (API < 31) default: exported=true if it has an
            # intent-filter. API 31+ requires explicit declaration, so an
            # absent attribute there usually means the build tools already
            # inlined it - treat conservatively based on intent-filter.
            exported = has_intent_filter

        permission = _attr(comp, "permission") or app_level_perm

        if exported and not permission:
            severity = "high" if kind == "provider" else "medium"
            emit({
                "category": "M1:2016-Improper Platform Usage (Exported Component)",
                "title": f"Exported {kind} without permission protection: {name}",
                "severity": severity,
                "confidence": "confirmed",
                "location": name,
                "evidence": (
                    f"<{tag} android:name=\"{name}\" android:exported="
                    f"\"{exported_attr or '(implicit via intent-filter)'}\"> declares no "
                    f"permission, so any app on the device can interact with it via Intents."
                ),
                "poc": f"adb shell am start -n <package>/{name}"
                if kind == "activity"
                else f"adb shell am {'startservice' if kind == 'service' else 'broadcast'} -n <package>/{name}",
                "remediation": (
                    f"Set android:exported=\"false\" if this {kind} is not meant to be used by "
                    "other apps, or protect it with a signature-level android:permission and "
                    "validate all incoming Intent data defensively."
                ),
            })


def analyze(path: str, emit):
    from androguard.core.apk import APK

    apk = APK(path)

    package = apk.get_package()
    emit({
        "category": "Info",
        "title": f"Package: {package}",
        "severity": "info",
        "confidence": "confirmed",
        "location": package or path,
        "evidence": (
            f"minSdk={apk.get_min_sdk_version()} targetSdk={apk.get_target_sdk_version()} "
            f"maxSdk={apk.get_max_sdk_version()}"
        ),
        "poc": "",
        "remediation": "",
    })

    target_sdk = 0
    try:
        target_sdk = int(apk.get_effective_target_sdk_version() or 0)
    except Exception:
        pass

    root = apk.get_android_manifest_xml()
    app_elem = root.find("application") if root is not None else None

    if app_elem is not None:
        if _attr(app_elem, "debuggable", "false").lower() == "true":
            emit({
                "category": "M9:2016-Reverse Engineering (Debuggable Build)",
                "title": "Application is debuggable (android:debuggable=\"true\")",
                "severity": "critical",
                "confidence": "confirmed",
                "location": "AndroidManifest.xml <application>",
                "evidence": "android:debuggable is set to true in the manifest",
                "poc": "adb shell run-as <package>  # works on a debuggable app even on non-rooted devices",
                "remediation": "Never ship debuggable=true in a release build; ensure your release build type disables it.",
            })

        if _attr(app_elem, "allowBackup", "true").lower() == "true":
            emit({
                "category": "M2:2016-Insecure Data Storage (Backup Enabled)",
                "title": "Application allows full backup (android:allowBackup=\"true\")",
                "severity": "medium",
                "confidence": "confirmed",
                "location": "AndroidManifest.xml <application>",
                "evidence": "android:allowBackup is true (or unset, which defaults to true)",
                "poc": "adb backup -f backup.ab <package>  # then extract with abe/dd to read app data without root",
                "remediation": (
                    "Set android:allowBackup=\"false\", or define a android:fullBackupContent "
                    "rule that excludes sensitive files (tokens, databases, keystores)."
                ),
            })

        cleartext = _attr(app_elem, "usesCleartextTraffic")
        if cleartext is None:
            # Default is true for targetSdk < 28, false for >= 28
            cleartext_effective = target_sdk < 28
        else:
            cleartext_effective = cleartext.lower() == "true"
        if cleartext_effective:
            emit({
                "category": "M3:2016-Insecure Communication (Cleartext Traffic)",
                "title": "Application permits cleartext (HTTP) traffic",
                "severity": "high",
                "confidence": "confirmed",
                "location": "AndroidManifest.xml <application>",
                "evidence": (
                    f"usesCleartextTraffic={cleartext!r}, effective targetSdk={target_sdk}"
                ),
                "poc": "Intercept app traffic with a proxy (e.g. mitmproxy) on an unencrypted network and observe plaintext HTTP requests.",
                "remediation": (
                    "Set android:usesCleartextTraffic=\"false\" and enforce HTTPS everywhere; "
                    "use a Network Security Config to explicitly control cleartext exceptions per-domain."
                ),
            })

        for tag, kind in (("activity", "activity"), ("service", "service"), ("receiver", "receiver"), ("provider", "provider")):
            _component_findings(app_elem, tag, kind, emit, target_sdk)

    for perm in apk.get_permissions():
        sev = DANGEROUS_PERMISSIONS.get(perm)
        if sev:
            emit({
                "category": "M1:2016-Improper Platform Usage (Sensitive Permission)",
                "title": f"Requests sensitive permission: {perm}",
                "severity": sev,
                "confidence": "confirmed",
                "location": perm,
                "evidence": f"Declared in AndroidManifest.xml: <uses-permission android:name=\"{perm}\"/>",
                "poc": "",
                "remediation": "Confirm this permission is actually required for a core feature and scoped minimally; excessive permissions increase attack surface if the app is compromised.",
            })

    # --- Secret scanning across archive contents ---
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.file_size > MAX_FILE_BYTES or info.file_size == 0:
                    continue
                if info.filename.startswith("META-INF/") and info.filename.endswith((".SF", ".RSA", ".DSA")):
                    continue
                try:
                    data = z.read(info.filename)
                except Exception:
                    continue
                for label, pattern in SECRET_PATTERNS:
                    matches = pattern.findall(data)
                    if not matches:
                        continue
                    sample = matches[0]
                    sample_str = sample.decode("latin-1", errors="replace") if isinstance(sample, bytes) else str(sample)
                    emit({
                        "category": "M9:2016-Reverse Engineering (Hardcoded Secret)",
                        "title": f"Possible {label} embedded in {info.filename}",
                        "severity": "high" if label != "Generic API Key/Secret Assignment" else "medium",
                        "confidence": "likely",
                        "location": info.filename,
                        "evidence": f"Pattern match (redacted): {sample_str[:6]}...{sample_str[-4:] if len(sample_str) > 10 else ''}",
                        "poc": f"unzip -p <apk> '{info.filename}' | strings | grep -i '{label.split()[0].lower()}'",
                        "remediation": "Remove hardcoded secrets from the app; use a backend proxy or runtime-fetched, short-lived credentials instead of embedding keys in the client.",
                    })
    except zipfile.BadZipFile:
        emit({
            "category": "Scanner",
            "title": "Could not read APK as a zip archive",
            "severity": "info",
            "confidence": "info",
            "location": path,
            "evidence": "File is not a valid APK/ZIP",
            "poc": "",
            "remediation": "",
        })
