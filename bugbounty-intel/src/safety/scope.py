"""Scope guard (§39) and request-safety modes (§40).

Authorized security-research tool. Without a scope.yaml, the tool defaults
to PASSIVE/OFFLINE mode and will not send any active probe.
"""
import fnmatch
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

MODES = ("PASSIVE", "SAFE_ACTIVE", "MANUAL")


class Scope:
    def __init__(self, allowed_domains=None, excluded_domains=None, excluded_paths=None):
        self.allowed_domains = allowed_domains or []
        self.excluded_domains = excluded_domains or []
        self.excluded_paths = excluded_paths or []

    @classmethod
    def load(cls, path):
        path = Path(path)
        if not path.is_file():
            return None
        if yaml is None:
            raise RuntimeError("PyYAML is required to load scope.yaml (pip install pyyaml)")
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(
            allowed_domains=data.get("allowed_domains", []),
            excluded_domains=data.get("excluded_domains", []),
            excluded_paths=data.get("excluded_paths", []),
        )

    def domain_allowed(self, domain):
        domain = domain.lower().strip()
        if any(fnmatch.fnmatch(domain, pat.lower()) for pat in self.excluded_domains):
            return False
        return any(fnmatch.fnmatch(domain, pat.lower()) for pat in self.allowed_domains)

    def path_allowed(self, path):
        return not any(fnmatch.fnmatch(path, pat) for pat in self.excluded_paths)


def resolve_mode(scope, requested_mode):
    """Enforce §39/§40: no scope file present -> force PASSIVE regardless of
    what the caller asked for."""
    if scope is None:
        return "PASSIVE"
    if requested_mode not in MODES:
        raise ValueError("mode must be one of {}".format(MODES))
    return requested_mode


def check_target(scope, mode, domain, path="/"):
    """Returns (ok, reason). Only SAFE_ACTIVE requires an in-scope check;
    PASSIVE never sends requests, MANUAL only displays payloads."""
    if mode == "PASSIVE":
        return False, "PASSIVE mode: no active requests are sent. Configure scope.yaml and pass --mode SAFE_ACTIVE to test live."
    if mode == "MANUAL":
        return False, "MANUAL mode: payloads are displayed for you to run yourself, not executed by this tool."
    if scope is None:
        return False, "No scope.yaml configured; refusing SAFE_ACTIVE requests. See §39."
    if not scope.domain_allowed(domain):
        return False, "'{}' is not in allowed_domains in scope.yaml".format(domain)
    if not scope.path_allowed(path):
        return False, "'{}' matches an excluded_paths pattern in scope.yaml".format(path)
    return True, "in scope"
