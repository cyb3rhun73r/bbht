#!/usr/bin/env python3
"""
Fetches/vendors the external attack tools that Bug Hunt HQ's Attack
Suggestions tab can drive, so the built app works without you separately
installing anything on PATH first.

Run once before build.bat (safe to re-run any time to update tools):

    python tools\\fetch_tools.py

What it does:
  - Downloads official prebuilt Windows binaries for nuclei, subfinder,
    ffuf and dalfox straight from their GitHub Releases (via the GitHub
    API, so it always grabs the current release - no hardcoded version).
  - Vendors sqlmap and git-dumper (pure Python, no separate runtime) as
    source from their official repos, run later via this app's own
    bundled interpreter.

wpscan is intentionally skipped - it needs a Ruby runtime, which is a poor
fit for a single-folder Windows bundle. Install it separately (see
README.md) if you want the wpscan suggestions to be runnable too.

Authorized security testing only - see the app's Legal/About tab.
"""
import io
import json
import os
import platform
import stat
import sys
import tarfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
GITHUB_API_LATEST = "https://api.github.com/repos/{}/releases/latest"
UA = {"User-Agent": "BugHuntHQ-tools-fetcher"}

# Compiled Go tools: fetched as the official prebuilt Windows release binary.
GO_TOOLS = {
    "nuclei": "projectdiscovery/nuclei",
    "subfinder": "projectdiscovery/subfinder",
    "ffuf": "ffuf/ffuf",
    "dalfox": "hahwul/dalfox",
}

# Pure-Python tools: vendored as source, no compiled binary needed.
PY_TOOLS = {
    "sqlmap": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
    "git-dumper": "https://github.com/arthaud/git-dumper/archive/refs/heads/master.zip",
}


def is_windows():
    return platform.system().lower() == "windows"


def os_tag():
    sysname = platform.system().lower()
    if sysname == "windows":
        return "windows"
    if sysname == "darwin":
        return "macos"
    return "linux"


def arch_tag():
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return "amd64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return machine


def pick_asset(assets):
    tag, arch = os_tag(), arch_tag()
    same_os = [a for a in assets if tag in a["name"].lower()]
    for a in same_os:
        if arch in a["name"].lower():
            return a
    return same_os[0] if same_os else None


def fetch_go_tool(name, repo):
    print("[*] Fetching {} ({})...".format(name, repo))
    try:
        req = urllib.request.Request(GITHUB_API_LATEST.format(repo), headers=UA)
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = json.load(resp)
    except Exception as e:
        print("    [!] Could not query GitHub releases for {}: {}".format(name, e))
        return

    asset = pick_asset(release.get("assets", []))
    if not asset:
        print("    [!] No matching release asset found for {} on this OS/arch; "
              "install it manually and put it on PATH instead.".format(name))
        return

    print("    [+] Downloading {}".format(asset["name"]))
    try:
        req = urllib.request.Request(asset["browser_download_url"], headers=UA)
        with urllib.request.urlopen(req, timeout=180) as resp:
            blob = resp.read()
    except Exception as e:
        print("    [!] Download failed for {}: {}".format(name, e))
        return

    exe_name = name + (".exe" if is_windows() else "")
    dest = os.path.join(HERE, exe_name)
    try:
        lower = asset["name"].lower()
        if lower.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                member = next((m for m in zf.namelist()
                               if os.path.basename(m).lower() == exe_name.lower()), None)
                if not member:
                    member = next((m for m in zf.namelist()
                                   if os.path.basename(m).lower().startswith(name.lower())), None)
                if not member:
                    raise RuntimeError("no matching file inside archive")
                with zf.open(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
        elif lower.endswith((".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
                member = next((m for m in tf.getmembers()
                               if os.path.basename(m.name).lower().startswith(name.lower())), None)
                if not member:
                    raise RuntimeError("no matching file inside archive")
                extracted = tf.extractfile(member)
                with open(dest, "wb") as dst:
                    dst.write(extracted.read())
        else:
            # a bare binary asset, not archived
            with open(dest, "wb") as dst:
                dst.write(blob)
    except Exception as e:
        print("    [!] Failed to extract {}: {}".format(name, e))
        return

    if os.path.isfile(dest):
        if not is_windows():
            os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC)
        print("    [+] {} ready at {}".format(name, dest))
    else:
        print("    [!] Could not locate the {} binary inside the downloaded archive.".format(name))


def fetch_py_tool(name, zip_url):
    print("[*] Vendoring {}...".format(name))
    dest = os.path.join(HERE, name)
    if os.path.isdir(dest):
        print("    [=] Already present at {}".format(dest))
        return
    try:
        req = urllib.request.Request(zip_url, headers=UA)
        with urllib.request.urlopen(req, timeout=180) as resp:
            blob = resp.read()
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            root = zf.namelist()[0].split("/")[0]
            zf.extractall(HERE)
        os.replace(os.path.join(HERE, root), dest)
        print("    [+] {} vendored at {}".format(name, dest))
    except Exception as e:
        print("    [!] Failed to vendor {}: {}".format(name, e))


def main():
    os.makedirs(HERE, exist_ok=True)
    print("Vendoring attack tools into: {}\n".format(HERE))
    for name, repo in GO_TOOLS.items():
        fetch_go_tool(name, repo)
    for name, url in PY_TOOLS.items():
        fetch_py_tool(name, url)
    print("\nDone. Bug Hunt HQ will auto-detect anything that landed in this folder.")
    print("wpscan needs a separate Ruby install - see README.md - it was skipped here.")


if __name__ == "__main__":
    main()
