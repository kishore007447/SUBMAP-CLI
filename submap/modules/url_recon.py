"""URL Reconnaissance Module (Katana + GAU integration)."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, parse_qs

from submap.core.models import URLRecord
from submap.utils.logger import get_logger

log = get_logger(__name__)

# File extensions considered interesting
INTERESTING_EXTENSIONS = {
    ".json", ".xml", ".yaml", ".yml", ".env", ".bak", ".sql",
    ".gz", ".zip", ".tar", ".log", ".conf", ".config", ".ini",
    ".sh", ".py", ".rb", ".php", ".asp", ".aspx", ".jsp",
    ".key", ".pem", ".cer", ".crt", ".p12",
}

ADMIN_PATTERNS = re.compile(
    r"(?:admin|administrator|panel|dashboard|manage|control|backend|"
    r"login|signin|auth|sso|cms|wp-admin|phpmyadmin)",
    re.I,
)

API_PATTERNS = re.compile(r"(?:/api/|/v\d+/|/graphql|/rest/)", re.I)


class URLRecon:
    """URL discovery using Katana, GAU and direct crawling."""

    def __init__(
        self,
        *,
        timeout: int = 30,
        threads: int = 5,
        rate_limit: int = 10,
        proxy: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.verbose = verbose

    async def collect(self, domains: list[str]) -> list[URLRecord]:
        """Collect URLs for given domains using all available tools."""
        all_urls: set[str] = set()
        records: list[URLRecord] = []

        for domain in domains:
            urls = await self._collect_for_domain(domain)
            for url in urls:
                if url not in all_urls:
                    all_urls.add(url)
                    records.append(self._classify_url(url))

        return records

    async def _collect_for_domain(self, domain: str) -> list[str]:
        urls: list[str] = []

        katana_available = await self._tool_available("katana")
        gau_available = await self._tool_available("gau")

        tasks = []
        if katana_available:
            tasks.append(self._run_katana(domain))
        if gau_available:
            tasks.append(self._run_gau(domain))

        if not tasks:
            log.info("Neither Katana nor GAU found — URL recon limited")
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in results:
            if isinstance(batch, list):
                urls.extend(batch)

        return list(set(urls))

    async def _run_katana(self, domain: str) -> list[str]:
        urls: list[str] = []
        proxy_args = ["-proxy", self.proxy] if self.proxy else []
        args = [
            "katana",
            "-u", f"https://{domain}",
            "-silent",
            "-depth", "3",
            "-jc",  # JS crawling
            "-timeout", str(self.timeout),
            "-rate-limit", str(self.rate_limit),
        ] + proxy_args

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            for line in stdout.decode(errors="ignore").splitlines():
                url = line.strip()
                if url.startswith("http"):
                    urls.append(url)
        except FileNotFoundError:
            log.debug("Katana not installed")
        except Exception as exc:
            log.debug("Katana error: %s", exc)

        return urls

    async def _run_gau(self, domain: str) -> list[str]:
        urls: list[str] = []
        args = [
            "gau",
            "--subs",
            "--threads", str(self.threads),
            domain,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            for line in stdout.decode(errors="ignore").splitlines():
                url = line.strip()
                if url.startswith("http"):
                    urls.append(url)
        except FileNotFoundError:
            log.debug("GAU not installed")
        except Exception as exc:
            log.debug("GAU error: %s", exc)

        return urls

    @staticmethod
    def _classify_url(url: str) -> URLRecord:
        parsed = urlparse(url)
        path = parsed.path or "/"
        extension = ""

        # Get extension
        if "." in path.split("/")[-1]:
            extension = "." + path.split("/")[-1].rsplit(".", 1)[-1].lower()

        # Get query parameters
        params = list(parse_qs(parsed.query).keys())

        # Classify
        is_interesting = extension in INTERESTING_EXTENSIONS
        category = "page"

        if API_PATTERNS.search(path):
            category = "api"
            is_interesting = True
        elif ADMIN_PATTERNS.search(path):
            category = "admin"
            is_interesting = True
        elif extension in (".js", ".ts"):
            category = "javascript"
        elif extension in (".css",):
            category = "stylesheet"
        elif extension in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"):
            category = "asset"
        elif extension in INTERESTING_EXTENSIONS:
            category = "sensitive"
            is_interesting = True

        return URLRecord(
            url=url,
            extension=extension,
            parameters=params,
            is_interesting=is_interesting,
            category=category,
        )

    @staticmethod
    async def _tool_available(tool: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                tool, "-version",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            return True
        except Exception:
            return False
