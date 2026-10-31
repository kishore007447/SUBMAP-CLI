"""Live Host Detection — HTTP/HTTPS probing, TLS, headers, tech fingerprinting."""
from __future__ import annotations

import asyncio
import re
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from submap.core.models import (
    LiveHost,
    SecurityHeaders,
    TLSInfo,
    Technology,
)
from submap.utils.logger import get_logger
from submap.utils.validator import is_private_ip, sanitize_url

log = get_logger(__name__)

# CDN fingerprints  (header/value pattern → provider name)
CDN_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-cache", "hit from cloudfront", "CloudFront"),
    ("via", "cloudfront", "CloudFront"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-cdn", "incapsula", "Incapsula"),
    ("x-iinfo", "", "Incapsula"),
    ("server", "sucuri", "Sucuri"),
]

# Technology signatures (header/pattern → tech name/category)
TECH_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (header_or_body, pattern, tech_name, category)
    ("server", r"nginx", "Nginx", "Web Server"),
    ("server", r"apache", "Apache", "Web Server"),
    ("server", r"iis", "IIS", "Web Server"),
    ("server", r"litespeed", "LiteSpeed", "Web Server"),
    ("server", r"openresty", "OpenResty", "Web Server"),
    ("x-powered-by", r"php", "PHP", "Language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "Framework"),
    ("x-powered-by", r"express", "Express.js", "Framework"),
    ("x-generator", r"wordpress", "WordPress", "CMS"),
    ("x-generator", r"drupal", "Drupal", "CMS"),
    ("body", r"wp-content|wp-includes", "WordPress", "CMS"),
    ("body", r"sites/default/files", "Drupal", "CMS"),
    ("body", r'content="Joomla', "Joomla", "CMS"),
    ("body", r"__NEXT_DATA__", "Next.js", "Framework"),
    ("body", r"nuxt", "Nuxt.js", "Framework"),
    ("body", r"gatsby", "Gatsby", "Framework"),
    ("body", r"<script.*react", "React", "JS Framework"),
    ("body", r"<script.*angular", "Angular", "JS Framework"),
    ("body", r"<script.*vue", "Vue.js", "JS Framework"),
    ("set-cookie", r"PHPSESSID", "PHP", "Language"),
    ("set-cookie", r"JSESSIONID", "Java", "Language"),
    ("set-cookie", r"ASP\.NET_SessionId", "ASP.NET", "Framework"),
    ("set-cookie", r"django", "Django", "Framework"),
    ("set-cookie", r"laravel_session", "Laravel", "Framework"),
]


class LiveHostDetector:
    """Probe discovered hosts for liveness and gather metadata."""

    def __init__(
        self,
        *,
        timeout: int = 10,
        retries: int = 2,
        threads: int = 20,
        rate_limit: int = 30,
        proxy: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.threads = threads
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.verbose = verbose
        self._sem = asyncio.Semaphore(threads)
        self._interval = 1.0 / rate_limit if rate_limit > 0 else 0

    async def probe_all(self, hostnames: list[str]) -> list[LiveHost]:
        """Probe all hostnames over HTTP and HTTPS."""
        tasks = [self._probe_host(h) for h in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        live: list[LiveHost] = []
        for r in results:
            if isinstance(r, LiveHost):
                live.append(r)
        return live

    async def _probe_host(self, hostname: str) -> LiveHost | None:
        """Try HTTPS first, then HTTP."""
        async with self._sem:
            if self._interval:
                await asyncio.sleep(self._interval)

            for scheme in ("https", "http"):
                url = f"{scheme}://{hostname}"
                result = await self._probe_url(url, hostname)
                if result:
                    return result
        return None

    async def _probe_url(self, url: str, hostname: str) -> LiveHost | None:
        safe = sanitize_url(url)
        if not safe:
            return None

        parsed = urlparse(url)
        # Reject private IPs in hostname
        if is_private_ip(parsed.hostname or ""):
            return None

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        proxies = self.proxy  # httpx accepts a plain URL string for mounts

        for attempt in range(self.retries + 1):
            try:
                start = time.monotonic()
                client_kwargs = dict(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False,  # noqa: S501 — intentional for recon
                    headers=headers,
                    max_redirects=5,
                )
                if self.proxy:
                    client_kwargs["proxy"] = self.proxy  # type: ignore[assignment]
                async with httpx.AsyncClient(**client_kwargs) as client:  # type: ignore[arg-type]
                    resp = await client.get(url)

                elapsed_ms = (time.monotonic() - start) * 1000

                # Collect redirect chain
                redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]

                # Parse title
                title = self._extract_title(resp.text[:4096])

                # Server header
                server = resp.headers.get("server", "")

                # Technology fingerprinting
                technologies = self._fingerprint(resp)

                # CDN detection
                is_cdn, cdn_provider = self._detect_cdn(resp)

                # Security headers
                sec_headers = self._parse_security_headers(hostname, resp)

                # TLS info (HTTPS only)
                tls_info: TLSInfo | None = None
                if parsed.scheme == "https":
                    tls_info = await self._get_tls_info(parsed.hostname or hostname)

                # IP address from response
                ip_address = ""
                if hasattr(resp, "extensions"):
                    network_stream = resp.extensions.get("network_stream")
                    if network_stream:
                        try:
                            ip_address = network_stream.get_extra_info("peername", ("",))[0]
                        except Exception:
                            pass

                content_length = int(resp.headers.get("content-length", 0))

                return LiveHost(
                    hostname=hostname,
                    url=url,
                    status_code=resp.status_code,
                    title=title,
                    final_url=str(resp.url),
                    redirect_chain=redirect_chain,
                    response_time_ms=round(elapsed_ms, 2),
                    server=server,
                    ip_address=ip_address,
                    content_length=content_length,
                    technologies=[t.name for t in technologies],
                    tls_info=tls_info,
                    security_headers=sec_headers,
                    is_cdn=is_cdn,
                    cdn_provider=cdn_provider,
                    webserver=server,
                )

            except httpx.ConnectError:
                break  # host is not listening — try next scheme
            except (httpx.TimeoutException, httpx.RemoteProtocolError):
                if attempt < self.retries:
                    await asyncio.sleep(0.5)
                    continue
                break
            except Exception as exc:
                log.debug("Probe error for %s: %s", url, exc)
                break

        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_title(html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            return " ".join(match.group(1).strip().split())[:200]
        return ""

    def _fingerprint(self, resp: httpx.Response) -> list[Technology]:
        techs: list[Technology] = []
        seen: set[str] = set()
        body_sample = resp.text[:8192].lower()

        for source, pattern, name, category in TECH_SIGNATURES:
            if name in seen:
                continue
            try:
                if source == "body":
                    if re.search(pattern, body_sample, re.IGNORECASE):
                        techs.append(Technology(name=name, category=category, evidence=f"body:{pattern}"))
                        seen.add(name)
                else:
                    val = resp.headers.get(source, "").lower()
                    if val and re.search(pattern, val, re.IGNORECASE):
                        techs.append(
                            Technology(name=name, category=category, evidence=f"{source}:{val[:100]}")
                        )
                        seen.add(name)
            except re.error:
                pass

        return techs

    @staticmethod
    def _detect_cdn(resp: httpx.Response) -> tuple[bool, str]:
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        for header, value, provider in CDN_SIGNATURES:
            h_val = headers_lower.get(header, "")
            if value == "" and h_val:
                return True, provider
            if value and value in h_val:
                return True, provider
        return False, ""

    @staticmethod
    def _parse_security_headers(hostname: str, resp: httpx.Response) -> SecurityHeaders:
        h = resp.headers
        missing: list[str] = []

        hsts = h.get("strict-transport-security")
        csp = h.get("content-security-policy")
        xcto = h.get("x-content-type-options")
        xfo = h.get("x-frame-options")
        rp = h.get("referrer-policy")
        pp = h.get("permissions-policy")
        xxss = h.get("x-xss-protection")

        for name, val in [
            ("HSTS", hsts),
            ("CSP", csp),
            ("X-Content-Type-Options", xcto),
            ("X-Frame-Options", xfo),
            ("Referrer-Policy", rp),
        ]:
            if not val:
                missing.append(name)

        return SecurityHeaders(
            hostname=hostname,
            hsts=hsts,
            csp=csp,
            x_content_type_options=xcto,
            x_frame_options=xfo,
            referrer_policy=rp,
            permissions_policy=pp,
            x_xss_protection=xxss,
            missing_headers=missing,
        )

    async def _get_tls_info(self, hostname: str) -> TLSInfo | None:
        """Retrieve TLS certificate info."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            cert = await loop.run_in_executor(None, self._fetch_cert, hostname, ctx)
            if not cert:
                return None

            not_before = datetime.strptime(
                cert.get("notBefore", ""), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc) if cert.get("notBefore") else None
            not_after = datetime.strptime(
                cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc) if cert.get("notAfter") else None

            now = datetime.now(timezone.utc)
            is_expired = not_after < now if not_after else False
            days_until_expiry: int | None = None
            if not_after:
                days_until_expiry = (not_after - now).days

            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            sans: list[str] = []
            for san_type, san_value in cert.get("subjectAltName", []):
                sans.append(san_value)

            hostname_mismatch = not any(
                self._hostname_matches(hostname, san) for san in sans
            ) if sans else False

            return TLSInfo(
                subject=subject,
                issuer=issuer,
                sans=sans,
                not_before=not_before,
                not_after=not_after,
                is_expired=is_expired,
                days_until_expiry=days_until_expiry,
                hostname_mismatch=hostname_mismatch,
            )
        except Exception as exc:
            log.debug("TLS info error for %s: %s", hostname, exc)
            return None

    @staticmethod
    def _fetch_cert(hostname: str, ctx: ssl.SSLContext) -> dict[str, Any] | None:
        import socket
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None

    @staticmethod
    def _hostname_matches(hostname: str, san: str) -> bool:
        if san.startswith("*."):
            return hostname.endswith(san[1:])
        return hostname.lower() == san.lower()
