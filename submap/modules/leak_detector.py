"""Information Exposure Detection Module."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

import httpx

from submap.core.models import LeakFinding
from submap.utils.logger import get_logger
from submap.utils.validator import sanitize_url

log = get_logger(__name__)

# Paths to check for common exposures
LEAK_PROBES: list[dict] = [
    # .env files
    {"path": "/.env", "type": "env_file", "expected_content": ["DB_", "SECRET", "KEY", "PASSWORD", "="]},
    {"path": "/.env.local", "type": "env_file", "expected_content": ["DB_", "SECRET", "="]},
    {"path": "/.env.production", "type": "env_file", "expected_content": ["DB_", "SECRET", "="]},
    {"path": "/.env.development", "type": "env_file", "expected_content": ["="]},
    {"path": "/.env.backup", "type": "env_file", "expected_content": ["="]},
    # Git exposure
    {"path": "/.git/config", "type": "git_exposure", "expected_content": ["[core]", "[remote", "url ="]},
    {"path": "/.git/HEAD", "type": "git_exposure", "expected_content": ["ref:", "HEAD"]},
    {"path": "/.git/COMMIT_EDITMSG", "type": "git_exposure", "expected_content": []},
    # Backup files
    {"path": "/backup.zip", "type": "backup_file", "expected_content": [], "check_content_type": ["application/zip", "application/octet-stream"]},
    {"path": "/backup.tar.gz", "type": "backup_file", "expected_content": [], "check_content_type": ["application/", "octet-stream"]},
    {"path": "/database.sql", "type": "backup_file", "expected_content": ["CREATE TABLE", "INSERT INTO"]},
    {"path": "/dump.sql", "type": "backup_file", "expected_content": ["CREATE TABLE", "INSERT INTO"]},
    {"path": "/db.sql", "type": "backup_file", "expected_content": ["CREATE", "INSERT"]},
    # Configuration files
    {"path": "/config.php", "type": "config_file", "expected_content": ["<?php", "define(", "config"]},
    {"path": "/config.yml", "type": "config_file", "expected_content": [":", "password", "secret"]},
    {"path": "/config.yaml", "type": "config_file", "expected_content": [":", "password", "secret"]},
    {"path": "/application.properties", "type": "config_file", "expected_content": ["spring.", "server.", "="]},
    {"path": "/wp-config.php", "type": "config_file", "expected_content": ["DB_NAME", "DB_PASSWORD"]},
    {"path": "/.htpasswd", "type": "config_file", "expected_content": [":", "$apr1", "$2y"]},
    {"path": "/web.config", "type": "config_file", "expected_content": ["connectionString", "<configuration>"]},
    # Debug / admin pages
    {"path": "/phpinfo.php", "type": "debug_page", "expected_content": ["PHP Version", "phpinfo()"]},
    {"path": "/info.php", "type": "debug_page", "expected_content": ["PHP Version"]},
    {"path": "/test.php", "type": "debug_page", "expected_content": ["PHP", "test"]},
    {"path": "/debug", "type": "debug_page", "expected_content": ["debug", "stack"]},
    {"path": "/trace", "type": "debug_page", "expected_content": ["trace"]},
    # Directory listings
    {"path": "/uploads/", "type": "directory_listing", "expected_content": ["Index of", "Parent Directory"]},
    {"path": "/files/", "type": "directory_listing", "expected_content": ["Index of", "Parent Directory"]},
    {"path": "/backup/", "type": "directory_listing", "expected_content": ["Index of", "Parent Directory"]},
    # Swagger / API docs (publicly exposed)
    {"path": "/swagger-ui.html", "type": "api_docs_exposed", "expected_content": ["swagger", "Swagger UI"]},
    {"path": "/swagger/index.html", "type": "api_docs_exposed", "expected_content": ["swagger"]},
    {"path": "/openapi.json", "type": "api_docs_exposed", "expected_content": ["openapi", "paths"]},
    {"path": "/swagger.json", "type": "api_docs_exposed", "expected_content": ["swagger", "paths"]},
    # Source maps
    {"path": "/js/app.js.map", "type": "source_map", "expected_content": ["sources", "mappings"]},
    {"path": "/static/js/main.js.map", "type": "source_map", "expected_content": ["sources"]},
    # Sensitive metadata
    {"path": "/server-status", "type": "server_metadata", "expected_content": ["Apache", "Server Status", "uptime"]},
    {"path": "/nginx_status", "type": "server_metadata", "expected_content": ["Active connections"]},
    {"path": "/.well-known/security.txt", "type": "info", "expected_content": ["Contact:"]},
    # Cloud metadata (read-only detection — we do NOT fetch actual metadata)
    # Docker / k8s exposure
    {"path": "/.dockerenv", "type": "container_exposure", "expected_content": []},
    {"path": "/docker-compose.yml", "type": "config_file", "expected_content": ["services:", "image:"]},
    # Log files
    {"path": "/logs/error.log", "type": "log_exposure", "expected_content": ["ERROR", "Exception", "Warning"]},
    {"path": "/error.log", "type": "log_exposure", "expected_content": ["ERROR", "PHP Warning"]},
    {"path": "/access.log", "type": "log_exposure", "expected_content": ["GET /", "POST /"]},
]

# Sensitive response header patterns
SENSITIVE_HEADERS = {
    "x-powered-by": "Technology disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
    "server": "Server version disclosure",
    "x-generator": "CMS/generator disclosure",
}

MAX_RESPONSE_BYTES = 50_000  # 50 KB cap for response body inspection


class LeakDetector:
    """Detect common information exposures and misconfigurations."""

    def __init__(
        self,
        *,
        timeout: int = 10,
        threads: int = 10,
        rate_limit: int = 15,
        proxy: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.verbose = verbose
        self._sem = asyncio.Semaphore(threads)
        self._interval = 1.0 / rate_limit if rate_limit > 0 else 0

    async def detect(self, live_hosts: list[str]) -> list[LeakFinding]:
        """Run all leak probes against live hosts."""
        tasks = [self._probe_host(h) for h in live_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[LeakFinding] = []
        for batch in results:
            if isinstance(batch, list):
                findings.extend(batch)
        return findings

    async def _probe_host(self, host: str) -> list[LeakFinding]:
        base_url = f"https://{host}" if not host.startswith("http") else host
        findings: list[LeakFinding] = []

        proxies = {"all://": self.proxy} if self.proxy else None
        headers = {
            "User-Agent": "SUBMAP/1.0 (Security Scanner)",
            "Accept": "*/*",
        }

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,  # noqa: S501
            follow_redirects=False,  # no redirects — check exactly the path
            proxies=proxies,
            headers=headers,
        ) as client:
            probe_sem = asyncio.Semaphore(5)

            async def probe(probe_def: dict) -> LeakFinding | None:
                async with probe_sem:
                    if self._interval:
                        await asyncio.sleep(self._interval)

                    path = probe_def["path"]
                    url = urljoin(base_url, path)
                    safe = sanitize_url(url)
                    if not safe:
                        return None

                    try:
                        # HEAD first to check existence
                        head_resp = await client.head(url)
                        if head_resp.status_code not in (200, 206):
                            return None

                        # Full GET with body size cap
                        resp = await client.get(
                            url,
                            headers={"Range": f"bytes=0-{MAX_RESPONSE_BYTES}"},
                        )

                        return self._verify_finding(probe_def, url, host, resp)

                    except Exception:
                        return None

            tasks = [probe(p) for p in LEAK_PROBES]
            results = await asyncio.gather(*tasks)
            for r in results:
                if r:
                    findings.append(r)

        return findings

    @staticmethod
    def _verify_finding(
        probe_def: dict,
        url: str,
        hostname: str,
        resp: httpx.Response,
    ) -> LeakFinding | None:
        """Verify a finding with response evidence — never on status code alone."""
        body = resp.text[:MAX_RESPONSE_BYTES]
        ct = resp.headers.get("content-type", "").lower()
        leak_type = probe_def["type"]
        expected = probe_def.get("expected_content", [])
        check_ct = probe_def.get("check_content_type", [])

        # Must pass content verification
        if expected:
            matched = any(e.lower() in body.lower() for e in expected)
            if not matched:
                return None

        if check_ct and not any(c.lower() in ct for c in check_ct):
            return None

        # Build a safe snippet (no raw secrets)
        snippet = body[:200].replace("\n", " ").replace("\r", "")
        # Redact potential secret values
        snippet = re.sub(
            r"(password|secret|key|token)\s*=\s*\S+",
            r"\1=****",
            snippet,
            flags=re.IGNORECASE,
        )

        return LeakFinding(
            url=url,
            hostname=hostname,
            leak_type=leak_type,
            status_code=resp.status_code,
            content_type=ct,
            content_snippet=snippet,
            evidence=f"HTTP {resp.status_code} — content matched: {expected[:2]}",
            redacted=True,
        )

    def check_sensitive_headers(
        self, hostname: str, resp_headers: dict[str, str]
    ) -> list[LeakFinding]:
        """Check response headers for information disclosure."""
        findings: list[LeakFinding] = []
        headers_lower = {k.lower(): v for k, v in resp_headers.items()}

        for header, description in SENSITIVE_HEADERS.items():
            val = headers_lower.get(header, "")
            if val and self._is_version_disclosure(header, val):
                findings.append(
                    LeakFinding(
                        url=f"https://{hostname}/",
                        hostname=hostname,
                        leak_type="header_disclosure",
                        evidence=f"{description}: {header}: {val[:100]}",
                        content_snippet=f"{header}: {val[:100]}",
                    )
                )
        return findings

    @staticmethod
    def _is_version_disclosure(header: str, value: str) -> bool:
        """Return True if the header value reveals a specific version."""
        return bool(re.search(r"\d+\.\d+", value))
