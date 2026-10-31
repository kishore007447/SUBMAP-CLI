"""Input validation utilities."""
from __future__ import annotations

import re
from pathlib import Path

import tldextract


_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# Private / reserved IP ranges that must not be scanned (SSRF prevention)
_PRIVATE_NETWORKS = [
    re.compile(r"^127\."),          # loopback
    re.compile(r"^10\."),           # RFC-1918
    re.compile(r"^192\.168\."),     # RFC-1918
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),  # RFC-1918
    re.compile(r"^169\.254\."),     # link-local
    re.compile(r"^::1$"),           # IPv6 loopback
    re.compile(r"^fc00:", re.I),    # IPv6 ULA
    re.compile(r"^fe80:", re.I),    # IPv6 link-local
]

# Cloud metadata endpoints
_METADATA_HOSTS = {
    "169.254.169.254",   # AWS / Azure / GCP
    "metadata.google.internal",
    "169.254.170.2",     # ECS
}


def validate_domain(domain: str) -> str | None:
    """Return normalised domain string or None if invalid."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return None
    if domain in _METADATA_HOSTS:
        return None
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return domain


def validate_domain_list(path: Path) -> list[str]:
    """Read a file of domains and return a validated, deduplicated list."""
    valid: list[str] = []
    seen: set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip().split("#")[0].strip()  # strip comments
            if not line:
                continue
            v = validate_domain(line)
            if v and v not in seen:
                seen.add(v)
                valid.append(v)
    except Exception:
        pass
    return valid


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is private / reserved."""
    return any(pat.match(ip) for pat in _PRIVATE_NETWORKS)


def is_metadata_host(host: str) -> bool:
    """Return True if the host is a cloud metadata endpoint."""
    return host.lower() in _METADATA_HOSTS


def sanitize_url(url: str) -> str | None:
    """Basic URL sanitiser — reject localhost / metadata destinations."""
    url = url.strip()
    lower = url.lower()
    bad_hosts = {"localhost", "127.0.0.1", "::1"} | _METADATA_HOSTS
    for bad in bad_hosts:
        if bad in lower:
            return None
    return url
