"""Subdomain Discovery Engine — passive, active, brute-force."""
from __future__ import annotations

import asyncio
import re
import subprocess
import tempfile
from pathlib import Path
from typing import AsyncIterator

import dns.asyncresolver
import httpx

from submap.core.models import Subdomain
from submap.utils.logger import get_logger

log = get_logger(__name__)

# Default public DNS resolvers
DEFAULT_RESOLVERS = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "208.67.222.222",
]

# Certificate Transparency log URLs
CT_LOGS = [
    "https://crt.sh/?q=%.{domain}&output=json",
    "https://crt.sh/?q={domain}&output=json",
]

# Additional passive sources
PASSIVE_SOURCES = {
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "threatminer": "https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
    "rapiddns": "https://rapiddns.io/subdomain/{domain}?full=1",
    "urlscan": "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
}

_SUBDOMAIN_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)


class SubdomainDiscovery:
    """Orchestrates all subdomain discovery methods."""

    def __init__(
        self,
        domain: str,
        *,
        passive: bool = True,
        active: bool = False,
        bruteforce: bool = False,
        recursive: bool = False,
        wordlist: Path | None = None,
        resolvers: Path | None = None,
        threads: int = 10,
        timeout: int = 10,
        rate_limit: int = 30,
        verbose: bool = False,
    ) -> None:
        self.domain = domain.lower().strip(".")
        self.passive = passive
        self.active = active
        self.bruteforce = bruteforce
        self.recursive = recursive
        self.wordlist = wordlist
        self.resolvers = resolvers
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self._seen: set[str] = set()
        self._resolver_list: list[str] = list(DEFAULT_RESOLVERS)

    # ── Public API ────────────────────────────────────────────────────────────

    async def discover(self) -> list[Subdomain]:
        """Run all enabled discovery methods and return deduplicated subdomains."""
        if self.resolvers and self.resolvers.exists():
            lines = self.resolvers.read_text().splitlines()
            self._resolver_list = [l.strip() for l in lines if l.strip()]

        results: list[Subdomain] = []

        tasks = []
        if self.passive:
            tasks.extend([
                self._crt_sh(),
                self._hackertarget(),
                self._alienvault(),
                self._urlscan(),
            ])

        if self.active:
            tasks.append(self._subfinder())
            tasks.append(self._amass())
            tasks.append(self._findomain())

        if self.bruteforce:
            tasks.append(self._dns_bruteforce())

        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in gathered:
            if isinstance(batch, Exception):
                log.debug("Discovery source error: %s", batch)
                continue
            for sub in batch:  # type: ignore[union-attr]
                if sub.hostname not in self._seen:
                    self._seen.add(sub.hostname)
                    results.append(sub)

        if self.recursive and results:
            extra = await self._recursive_discover(results)
            for sub in extra:
                if sub.hostname not in self._seen:
                    self._seen.add(sub.hostname)
                    results.append(sub)

        return results

    # ── Passive: Certificate Transparency ─────────────────────────────────────

    async def _crt_sh(self) -> list[Subdomain]:
        subdomains: list[Subdomain] = []
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "SUBMAP/1.0"})
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        names = entry.get("name_value", "")
                        for name in names.replace("*.", "").split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{self.domain}") or name == self.domain:
                                subdomains.append(
                                    Subdomain(hostname=name, source="crt.sh")
                                )
        except Exception as exc:
            log.debug("crt.sh error: %s", exc)
        return self._dedupe(subdomains)

    # ── Passive: HackerTarget ─────────────────────────────────────────────────

    async def _hackertarget(self) -> list[Subdomain]:
        subdomains: list[Subdomain] = []
        url = PASSIVE_SOURCES["hackertarget"].format(domain=self.domain)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "SUBMAP/1.0"})
                if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                    for line in resp.text.splitlines():
                        parts = line.split(",")
                        if parts:
                            name = parts[0].strip().lower()
                            if name.endswith(self.domain):
                                subdomains.append(
                                    Subdomain(hostname=name, source="hackertarget")
                                )
        except Exception as exc:
            log.debug("HackerTarget error: %s", exc)
        return self._dedupe(subdomains)

    # ── Passive: AlienVault OTX ───────────────────────────────────────────────

    async def _alienvault(self) -> list[Subdomain]:
        subdomains: list[Subdomain] = []
        url = PASSIVE_SOURCES["alienvault"].format(domain=self.domain)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "SUBMAP/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").lower()
                        if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                            subdomains.append(
                                Subdomain(hostname=hostname, source="alienvault")
                            )
        except Exception as exc:
            log.debug("AlienVault error: %s", exc)
        return self._dedupe(subdomains)

    # ── Passive: URLScan.io ───────────────────────────────────────────────────

    async def _urlscan(self) -> list[Subdomain]:
        subdomains: list[Subdomain] = []
        url = PASSIVE_SOURCES["urlscan"].format(domain=self.domain)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "SUBMAP/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        domain = page.get("domain", "").lower()
                        if domain.endswith(f".{self.domain}") or domain == self.domain:
                            subdomains.append(
                                Subdomain(hostname=domain, source="urlscan")
                            )
        except Exception as exc:
            log.debug("URLScan error: %s", exc)
        return self._dedupe(subdomains)

    # ── Active: External tool helpers ─────────────────────────────────────────

    async def _run_external_tool(
        self, tool: str, args: list[str], source_name: str
    ) -> list[Subdomain]:
        """Run an external tool safely and parse hostnames from stdout."""
        subdomains: list[Subdomain] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                tool, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            for line in stdout.decode(errors="ignore").splitlines():
                name = line.strip().lower()
                if name.endswith(f".{self.domain}") or name == self.domain:
                    subdomains.append(Subdomain(hostname=name, source=source_name))
        except FileNotFoundError:
            log.debug("%s not installed — skipping", tool)
        except Exception as exc:
            log.debug("%s error: %s", tool, exc)
        return self._dedupe(subdomains)

    async def _subfinder(self) -> list[Subdomain]:
        return await self._run_external_tool(
            "subfinder", ["-d", self.domain, "-silent", "-all"], "subfinder"
        )

    async def _amass(self) -> list[Subdomain]:
        return await self._run_external_tool(
            "amass", ["enum", "-passive", "-d", self.domain, "-silent"], "amass"
        )

    async def _findomain(self) -> list[Subdomain]:
        return await self._run_external_tool(
            "findomain", ["-t", self.domain, "-q"], "findomain"
        )

    # ── Active: DNS brute-force ───────────────────────────────────────────────

    async def _dns_bruteforce(self) -> list[Subdomain]:
        """Brute-force subdomains from a wordlist."""
        words: list[str] = []

        if self.wordlist and self.wordlist.exists():
            words = [
                w.strip()
                for w in self.wordlist.read_text(encoding="utf-8").splitlines()
                if w.strip() and not w.startswith("#")
            ]
        else:
            # Built-in minimal wordlist
            words = self._default_wordlist()

        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = self._resolver_list[:4]
        resolver.timeout = 3
        resolver.lifetime = 5

        subdomains: list[Subdomain] = []
        sem = asyncio.Semaphore(self.threads)

        async def probe(word: str) -> None:
            hostname = f"{word}.{self.domain}"
            async with sem:
                try:
                    answer = await resolver.resolve(hostname, "A")
                    ips = [r.address for r in answer]
                    subdomains.append(
                        Subdomain(hostname=hostname, source="bruteforce", ip_addresses=ips, resolved=True)
                    )
                except Exception:
                    pass

        await asyncio.gather(*[probe(w) for w in words])
        return self._dedupe(subdomains)

    # ── Recursive discovery ───────────────────────────────────────────────────

    async def _recursive_discover(self, base: list[Subdomain]) -> list[Subdomain]:
        """Run passive discovery on each unique second-level subdomain."""
        extra: list[Subdomain] = []
        checked: set[str] = set()
        for sub in base:
            parts = sub.hostname.split(".")
            if len(parts) > 3:
                pivot = ".".join(parts[1:])
                if pivot not in checked and pivot != self.domain:
                    checked.add(pivot)
                    new = await self._crt_sh_for(pivot)
                    extra.extend(new)
        return extra

    async def _crt_sh_for(self, domain: str) -> list[Subdomain]:
        subdomains: list[Subdomain] = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers={"User-Agent": "SUBMAP/1.0"})
                if resp.status_code == 200:
                    for entry in resp.json():
                        for name in entry.get("name_value", "").replace("*.", "").split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{self.domain}"):
                                subdomains.append(Subdomain(hostname=name, source="crt.sh-recursive"))
        except Exception:
            pass
        return subdomains

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _dedupe(self, subs: list[Subdomain]) -> list[Subdomain]:
        seen: set[str] = set()
        out: list[Subdomain] = []
        for s in subs:
            h = s.hostname.lower().strip(".")
            if h and h not in seen and (h.endswith(f".{self.domain}") or h == self.domain):
                seen.add(h)
                s.hostname = h
                out.append(s)
        return out

    @staticmethod
    def _default_wordlist() -> list[str]:
        return [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
            "vpn", "ns1", "ns2", "mx", "api", "dev", "staging", "test", "admin",
            "portal", "app", "mobile", "m", "static", "cdn", "media", "img",
            "assets", "upload", "download", "files", "docs", "help", "support",
            "status", "monitor", "git", "gitlab", "github", "jira", "confluence",
            "jenkins", "ci", "build", "deploy", "prod", "production", "beta",
            "alpha", "demo", "sandbox", "stg", "uat", "qa", "corp", "internal",
            "intranet", "extranet", "secure", "login", "auth", "sso", "ldap",
            "ad", "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
            "elastic", "kibana", "grafana", "prometheus", "splunk", "log",
            "analytics", "stats", "metrics", "dashboard", "panel", "cpanel",
            "whm", "plesk", "directadmin", "phpmyadmin", "backup", "shop",
            "store", "pay", "payment", "billing", "invoice", "crm", "erp",
            "hr", "blog", "news", "forum", "community", "wiki", "kb",
            "search", "cdn1", "cdn2", "img1", "img2", "v1", "v2", "v3",
            "api1", "api2", "gateway", "proxy", "lb", "loadbalancer",
        ]
