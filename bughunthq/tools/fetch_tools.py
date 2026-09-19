#!/usr/bin/env python3
"""
Fetches/vendors the external attack tools that Bug Hunt HQ's Attack
Suggestions tab can drive, so the built app works without you separately
installing anything on PATH first.

Run once before build.bat (safe to re-run any time to update tools):

    python tools\\fetch_tools.py

What it does, mapped to OWASP Top 10 (2021):
  - A01 Broken Access Control    -> ffuf (already vendored for the LFI/dir
    suggestions), corsy (CORS misconfig)
  - A02 Cryptographic Failures   -> tlsx (TLS/cipher checks)
  - A03 Injection                -> sqlmap (SQLi), dalfox (XSS), commix (OS
    command injection)
  - A05 Security Misconfiguration -> nuclei, git-dumper
  - A06 Vulnerable & Outdated Components -> nuclei, trivy, wpscan
  - A07 Identification & Auth Failures -> jwt_tool
  - A10 Server-Side Request Forgery -> interactsh-client
  (A04/A08/A09 are methodology/manual-review categories with no single
  matching offensive tool - the app's suggestions still flag them.)

Compiled (Go) tools are downloaded as the official prebuilt Windows binary
straight from each project's GitHub Releases (via the GitHub API, so it
always grabs the current release - no hardcoded version). Pure-Python tools
are vendored as source and run later via this app's own bundled interpreter
- no separate Python/Go install needed on the machine running the built exe.

Each vendored Python tool's OWN requirements.txt (whatever it currently
declares upstream - not a hardcoded guess) is pip-installed into this same
environment automatically, and the package names are written to
tools\\extra-packages.txt so build.bat can tell PyInstaller to freeze them
into the exe too (see build.bat). If this script runs inside the built exe
itself (no pip available there), that step is skipped with a clear message
- it only needs to happen once, in a real Python environment, before build.bat
packages the app.

wpscan is intentionally skipped - it needs a Ruby runtime, which is a poor
fit for a single-folder Windows bundle. Install it separately (see
README.md) if you want the wpscan suggestions to be runnable too.

Authorized security testing only - see the app's Legal/About tab.
"""
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
GITHUB_API_LATEST = "https://api.github.com/repos/{}/releases/latest"
UA = {"User-Agent": "BugHuntHQ-tools-fetcher"}

# Compiled Go tools: fetched as the official prebuilt Windows release binary.
# Value is either "owner/repo" or (owner/repo, asset_name_hint) for repos
# whose releases bundle more than one binary (client vs server, etc).
GO_TOOLS = {
    "nuclei": "projectdiscovery/nuclei",
    "subfinder": "projectdiscovery/subfinder",
    "ffuf": "ffuf/ffuf",
    "dalfox": "hahwul/dalfox",
    "tlsx": "projectdiscovery/tlsx",
    "trivy": "aquasecurity/trivy",
    "interactsh-client": ("projectdiscovery/interactsh", "client"),
}

# Pure-Python tools: vendored as source, no compiled binary needed.
PY_TOOLS = {
    "sqlmap": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
    "git-dumper": "https://github.com/arthaud/git-dumper/archive/refs/heads/master.zip",
    "commix": "https://github.com/commixproject/commix/archive/refs/heads/master.zip",
    "jwt_tool": "https://github.com/ticarpi/jwt_tool/archive/refs/heads/master.zip",
    "corsy": "https://github.com/s0md3v/Corsy/archive/refs/heads/master.zip",
}


def is_windows():
    return platform.system().lower() == "windows"


def norm(s):
    """Lowercase and strip separators so 'Windows-64bit' == 'windows_amd64'
    style naming differences between projects don't break matching."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def os_tag():
    sysname = platform.system().lower()
    if sysname == "windows":
        return "windows"
    if sysname == "darwin":
        return "macos"
    return "linux"


def arch_aliases():
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return ["amd64", "x8664", "x64", "64bit"]
    if machine in ("arm64", "aarch64"):
        return ["arm64", "aarch64"]
    return [machine]


def pick_asset(assets, name_hint=None):
    tag = norm(os_tag())
    same_os = [a for a in assets if tag in norm(a["name"])]
    if name_hint:
        narrowed = [a for a in same_os if norm(name_hint) in norm(a["name"])]
        if narrowed:
            same_os = narrowed
    aliases = [norm(a) for a in arch_aliases()]
    for a in same_os:
        n = norm(a["name"])
        if any(alias in n for alias in aliases):
            return a
    return same_os[0] if same_os else None


def fetch_go_tool(name, repo_spec):
    repo, name_hint = repo_spec if isinstance(repo_spec, tuple) else (repo_spec, None)
    print("[*] Fetching {} ({})...".format(name, repo))
    try:
        req = urllib.request.Request(GITHUB_API_LATEST.format(repo), headers=UA)
        with urllib.request.urlopen(req, timeout=30) as resp:
            release = json.load(resp)
    except Exception as e:
        print("    [!] Could not query GitHub releases for {}: {}".format(name, e))
        return

    asset = pick_asset(release.get("assets", []), name_hint)
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


def pip_is_usable():
    """False inside a frozen exe (no pip/site-packages to install into) or
    when pip just isn't importable in this interpreter."""
    if getattr(sys, "frozen", False):
        return False
    try:
        import pip  # noqa: F401
        return True
    except ImportError:
        return False


def package_name(requirement_line):
    """'pycryptodomex>=3.9' -> 'pycryptodomex'."""
    line = requirement_line.split("#", 1)[0].strip()
    m = re.match(r"^[A-Za-z0-9_.\-]+", line)
    return m.group(0) if m else None


def import_names_for(pip_name):
    """PyInstaller's --collect-all needs the actual importable top-level
    module name, which often differs from the PyPI distribution name
    (PySocks -> socks, beautifulsoup4 -> bs4, pycryptodomex -> Cryptodome,
    requests-pkcs12 -> requests_pkcs12). Resolve it from the package's own
    installed metadata instead of guessing."""
    try:
        import importlib.metadata as im
    except ImportError:
        return [pip_name]
    target = pip_name.lower().replace("_", "-")
    try:
        mapping = im.packages_distributions()
        found = [imp for imp, dists in mapping.items()
                 if any(d.lower().replace("_", "-") == target for d in dists)]
        if found:
            return found
    except Exception:
        pass
    try:
        top_level = im.distribution(pip_name).read_text("top_level.txt")
        if top_level:
            names = [n.strip() for n in top_level.splitlines() if n.strip()]
            if names:
                return names
    except Exception:
        pass
    return [pip_name]  # best-effort fallback - matches the old behavior


def install_tool_requirements(name, tool_dir, all_packages):
    req_path = os.path.join(tool_dir, "requirements.txt")
    if not os.path.isfile(req_path):
        return
    with open(req_path, "r", encoding="utf-8", errors="ignore") as fh:
        lines = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
    pkgs = [package_name(l) for l in lines]

    if not pip_is_usable():
        all_packages.update(p for p in pkgs if p)
        print("    [!] {} declares dependencies ({}) but pip isn't available in this "
              "environment - run fetch_tools.py from a normal `python` install (inside "
              "build.bat's venv) so they get installed and frozen into the exe.".format(
                  name, ", ".join(pkgs)))
        return

    # Installed one package at a time (not `pip install -r file` as a single
    # transaction) so one upstream tool's fussy legacy dependency doesn't
    # block the rest of that tool's - or every other tool's - packages.
    print("    [*] Installing {}'s dependencies: {}".format(name, ", ".join(pkgs)))
    for pkg in pkgs:
        if not pkg:
            continue
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", pkg],
                            check=True, timeout=180)
            imports = import_names_for(pkg)
            all_packages.update(imports)
            print("        [+] {} (import: {})".format(pkg, ", ".join(imports)))
        except Exception as e:
            all_packages.add(pkg)  # still record something rather than nothing
            print("        [!] {} failed to install ({}) - the tool may not run until "
                  "this is resolved (try `pip install {}` by hand).".format(pkg, e, pkg))


def fetch_py_tool(name, zip_url, all_packages):
    print("[*] Vendoring {}...".format(name))
    dest = os.path.join(HERE, name)
    if os.path.isdir(dest):
        print("    [=] Already present at {}".format(dest))
        install_tool_requirements(name, dest, all_packages)
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
        return
    install_tool_requirements(name, dest, all_packages)


def main():
    os.makedirs(HERE, exist_ok=True)
    print("Vendoring attack tools into: {}\n".format(HERE))
    for name, repo in GO_TOOLS.items():
        fetch_go_tool(name, repo)

    all_packages = set()
    for name, url in PY_TOOLS.items():
        fetch_py_tool(name, url, all_packages)

    if all_packages:
        manifest = os.path.join(HERE, "extra-packages.txt")
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(all_packages)) + "\n")
        print("\n[+] Wrote {} ({} package(s)) - build.bat freezes these into the exe "
              "with PyInstaller's --collect-all.".format(manifest, len(all_packages)))

    print("\nDone. Bug Hunt HQ will auto-detect anything that landed in this folder.")
    print("wpscan needs a separate Ruby install - see README.md - it was skipped here.")


if __name__ == "__main__":
    main()
