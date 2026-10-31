"""JavaScript Analysis Module."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from submap.core.models import JSFinding
from submap.utils.logger import get_logger

log = get_logger(__name__)

# Patterns for endpoint extraction from JS
ENDPOINT_PATTERNS = [
    re.compile(r"""['"`]((?:/[a-zA-Z0-9_\-\.]+){2,})['"`]"""),
    re.compile(r"""(?:fetch|axios|http|request)\s*\(\s*['"`]([^'"`\n]{3,200})['"`]""", re.I),
    re.compile(r"""url\s*[:=]\s*['"`]([^'"`\n]{3,200})['"`]""", re.I),
    re.compile(r"""['"`](https?://[^'"`\s]{5,200})['"`]"""),
]

# Secret / credential patterns
SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_\-]?key|apikey)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]""", re.I), "API Key"),
    (re.compile(r"""(?:secret|password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{6,})['"`]""", re.I), "Secret"),
    (re.compile(r"""(?:access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['"`]([^'"`\s]{10,})['"`]""", re.I), "Token"),
    (re.compile(r"""(?:aws[_\-]?access[_\-]?key)\s*[:=]\s*['"`]([A-Z0-9]{16,})['"`]""", re.I), "AWS Key"),
    (re.compile(r"""AKIA[0-9A-Z]{16}"""), "AWS Access Key"),
    (re.compile(r"""(?:client[_\-]?secret)\s*[:=]\s*['"`]([^'"`\s]{10,})['"`]""", re.I), "Client Secret"),
    (re.compile(r"""(?:private[_\-]?key)\s*[:=]\s*['"`]([^'"`\s]{10,})['"`]""", re.I), "Private Key"),
    (re.compile(r"""(?:bearer)\s+([A-Za-z0-9\-._~+/]+=*)""", re.I), "Bearer Token"),
]

# Source map detection
SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(.+?)(?:\s|$)", re.MULTILINE)

JS_EXTENSION_RE = re.compile(r"\.js(?:\?[^\"']*)?$", re.I)
JS_LINK_RE = re.compile(r"""(?:src|href)=['"]([^'"]*\.js[^'"]*?)['"]""", re.I)


class JSAnalyzer:
    """Discover and analyse JavaScript files for endpoints and secrets."""

    def __init__(
        self,
        *,
        timeout: int = 15,
        threads: int = 5,
        rate_limit: int = 10,
        proxy: str | None = None,
        max_js_size: int = 5_000_000,  # 5 MB
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.max_js_size = max_js_size
        self._sem = asyncio.Semaphore(threads)
        self._interval = 1.0 / rate_limit if rate_limit > 0 else 0

    async def analyze_hosts(
        self, live_hosts: list[str]
    ) -> tuple[list[JSFinding], dict[str, str]]:
        """Discover and analyse JS files from live hosts.

        Returns:
            findings: List of JSFinding objects.
            js_content: Dict mapping JS URL → content (for API discovery).
        """
        findings: list[JSFinding] = []
        js_content: dict[str, str] = {}

        tasks = [self._process_host(h) for h in live_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for batch in results:
            if isinstance(batch, tuple):
                host_findings, host_content = batch
                findings.extend(host_findings)
                js_content.update(host_content)

        return findings, js_content

    async def _process_host(
        self, host: str
    ) -> tuple[list[JSFinding], dict[str, str]]:
        """Discover JS files from a host and analyse them."""
        base_url = f"https://{host}" if not host.startswith("http") else host
        js_urls = await self._discover_js_urls(base_url)

        findings: list[JSFinding] = []
        js_content: dict[str, str] = {}

        tasks = [self._analyze_js(js_url, host) for js_url in js_urls[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for js_url, result in zip(js_urls[:30], results):
            if isinstance(result, tuple):
                finding, content = result
                if finding:
                    findings.append(finding)
                if content:
                    js_content[js_url] = content

        return findings, js_content

    async def _discover_js_urls(self, base_url: str) -> list[str]:
        """Fetch the page and extract JS file URLs."""
        js_urls: list[str] = []
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, verify=False, follow_redirects=True
            ) as client:
                resp = await client.get(base_url)
                if resp.status_code == 200:
                    for match in JS_LINK_RE.finditer(resp.text):
                        src = match.group(1)
                        full_url = urljoin(base_url, src)
                        if full_url not in js_urls:
                            js_urls.append(full_url)
        except Exception as exc:
            log.debug("JS discovery error for %s: %s", base_url, exc)
        return js_urls

    async def _analyze_js(
        self, js_url: str, parent_hostname: str
    ) -> tuple[JSFinding | None, str | None]:
        """Download and analyse a single JS file."""
        async with self._sem:
            if self._interval:
                await asyncio.sleep(self._interval)

            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, verify=False, follow_redirects=True
                ) as client:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        return None, None

                    content_length = int(resp.headers.get("content-length", 0))
                    if content_length > self.max_js_size:
                        return None, None

                    content = resp.text
                    if len(content) > self.max_js_size:
                        content = content[: self.max_js_size]

                    finding = self._parse_js(content, js_url, parent_hostname)
                    return finding, content

            except Exception as exc:
                log.debug("JS analysis error for %s: %s", js_url, exc)
                return None, None

    def _parse_js(self, content: str, js_url: str, parent_hostname: str) -> JSFinding:
        finding = JSFinding(js_url=js_url, parent_hostname=parent_hostname)

        # Source map detection
        sm_match = SOURCE_MAP_RE.search(content)
        if sm_match:
            finding.has_source_map = True
            finding.source_map_url = sm_match.group(1).strip()

        # Endpoint extraction
        endpoints: set[str] = set()
        api_routes: set[str] = set()
        urls: set[str] = set()

        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1).strip()
                if not value or len(value) < 3:
                    continue
                if value.startswith("http"):
                    urls.add(value[:500])
                elif value.startswith("/"):
                    if re.search(r"/api/|/v\d+/|/graphql", value, re.I):
                        api_routes.add(value)
                    else:
                        endpoints.add(value)

        finding.endpoints = list(endpoints)[:100]
        finding.api_routes = list(api_routes)[:100]
        finding.urls = list(urls)[:100]

        # Secret detection (redacted in output)
        for pattern, secret_type in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                try:
                    raw = match.group(1) if pattern.groups else match.group(0)
                except IndexError:
                    raw = match.group(0)

                # Redact: only show first 4 + last 2 chars
                if len(raw) > 8:
                    redacted = raw[:4] + "****" + raw[-2:]
                else:
                    redacted = "****"

                finding.hardcoded_secrets.append(
                    {
                        "type": secret_type,
                        "redacted_value": redacted,
                        "context": content[max(0, match.start() - 30) : match.end() + 30].strip()[:100],
                    }
                )

        # Suspicious patterns (not secrets but worth reviewing)
        susp_patterns = [
            (re.compile(r"localhost:\d+", re.I), "localhost reference"),
            (re.compile(r"127\.0\.0\.1", re.I), "loopback IP reference"),
            (re.compile(r"internal\.", re.I), "internal hostname"),
            (re.compile(r"debug\s*[=:]\s*true", re.I), "debug mode enabled"),
            (re.compile(r"console\.log\(", re.I), "console.log present"),
        ]
        for pattern, desc in susp_patterns:
            if pattern.search(content):
                finding.suspicious_patterns.append({"type": desc})

        return finding
