"""API Discovery Engine."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from submap.core.models import APIEndpoint
from submap.utils.logger import get_logger
from submap.utils.validator import sanitize_url

log = get_logger(__name__)

# Common API paths to probe
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphiql", "/graph",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/api/swagger", "/api/swagger-ui.html",
    "/openapi.json", "/openapi.yaml", "/api/openapi.json",
    "/swagger.json", "/swagger.yaml", "/api-docs", "/api-docs.json",
    "/docs", "/redoc",
    "/health", "/healthz", "/health/check", "/api/health",
    "/status", "/ping", "/ready", "/live",
    "/metrics", "/actuator", "/actuator/health", "/actuator/info",
    "/api/users", "/api/auth", "/api/login", "/api/logout",
    "/api/register", "/api/token", "/api/refresh",
    "/admin/api", "/internal/api",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/oauth/token", "/oauth/authorize",
    "/rest", "/rest/v1", "/rest/v2",
    "/json", "/json/v1",
    "/api/search", "/api/data", "/api/list", "/api/config",
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'

# Patterns indicating API responses
API_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "application/vnd.api+json",
    "application/hal+json",
    "application/graphql+json",
}

API_PATH_RE = re.compile(
    r"""(?:['"`\s])((?:/api/|/v\d+/|/graphql|/swagger|/openapi|/rest/)"""
    r"""[a-zA-Z0-9/_\-\.?=&%#]*?)(?:['"`\s\)])""",
    re.IGNORECASE,
)


class APIDiscovery:
    """Discover REST, GraphQL, and other API endpoints."""

    def __init__(
        self,
        *,
        timeout: int = 10,
        threads: int = 10,
        rate_limit: int = 20,
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

    async def discover(
        self, live_hosts: list[str], js_content: dict[str, str] | None = None
    ) -> list[APIEndpoint]:
        """Discover API endpoints for a list of live hosts."""
        endpoints: list[APIEndpoint] = []
        seen: set[str] = set()

        # Probe common API paths
        tasks = [self._probe_host(host) for host in live_hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in results:
            if isinstance(batch, list):
                for ep in batch:
                    if ep.url not in seen:
                        seen.add(ep.url)
                        endpoints.append(ep)

        # Extract from JS content
        if js_content:
            for js_url, content in js_content.items():
                extracted = self._extract_from_js(content, js_url, live_hosts)
                for ep in extracted:
                    if ep.url not in seen:
                        seen.add(ep.url)
                        endpoints.append(ep)

        return endpoints

    async def _probe_host(self, host: str) -> list[APIEndpoint]:
        """Probe a host for common API paths."""
        endpoints: list[APIEndpoint] = []
        scheme = "https" if not host.startswith("http") else ""
        base_url = f"https://{host}" if not host.startswith("http") else host

        proxies = {"all://": self.proxy} if self.proxy else None

        headers = {
            "User-Agent": "SUBMAP/1.0 (API Discovery)",
            "Accept": "application/json, text/html, */*",
        }

        client_kwargs: dict = dict(
            timeout=self.timeout,
            verify=False,  # noqa: S501
            follow_redirects=True,
            headers=headers,
        )
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        async with httpx.AsyncClient(**client_kwargs) as client:
            sem = asyncio.Semaphore(5)  # limit concurrent per-host

            async def probe_path(path: str) -> APIEndpoint | None:
                async with sem:
                    if self._interval:
                        await asyncio.sleep(self._interval)
                    url = urljoin(base_url, path)
                    safe = sanitize_url(url)
                    if not safe:
                        return None
                    try:
                        resp = await client.get(url)
                        ct = resp.headers.get("content-type", "").lower().split(";")[0].strip()
                        is_api = (
                            any(act in ct for act in API_CONTENT_TYPES)
                            or resp.status_code in (200, 201, 400, 401, 403, 404, 405)
                        )
                        if resp.status_code not in (500, 502, 503, 504) and is_api:
                            api_type = self._classify_api_type(path, resp)
                            is_documented = any(
                                kw in path.lower()
                                for kw in ("swagger", "openapi", "docs", "redoc", "graphiql")
                            )
                            return APIEndpoint(
                                url=url,
                                path=path,
                                api_type=api_type,
                                status_code=resp.status_code,
                                content_type=ct,
                                parent_hostname=host,
                                source="path-probe",
                                is_documented=is_documented,
                                requires_auth=resp.status_code in (401, 403),
                            )
                    except Exception:
                        pass
                    return None

            results = await asyncio.gather(*[probe_path(p) for p in COMMON_API_PATHS])
            for r in results:
                if r:
                    endpoints.append(r)

        return endpoints

    def _extract_from_js(
        self, content: str, js_url: str, live_hosts: list[str]
    ) -> list[APIEndpoint]:
        """Extract API paths from JavaScript source."""
        endpoints: list[APIEndpoint] = []
        seen: set[str] = set()

        # Determine base host from JS URL
        parsed = urlparse(js_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for match in API_PATH_RE.finditer(content):
            path = match.group(1).strip()
            if not path or len(path) > 200:
                continue
            url = urljoin(base, path)
            if url not in seen:
                seen.add(url)
                endpoints.append(
                    APIEndpoint(
                        url=url,
                        path=path,
                        api_type=self._classify_by_path(path),
                        parent_hostname=parsed.netloc,
                        source="js-extraction",
                    )
                )

        return endpoints

    @staticmethod
    def _classify_api_type(path: str, resp: httpx.Response) -> str:
        path_lower = path.lower()
        ct = resp.headers.get("content-type", "").lower()

        if "graphql" in path_lower or "graphiql" in path_lower:
            return "GraphQL"
        if "swagger" in path_lower or "openapi" in path_lower or "api-docs" in path_lower:
            return "OpenAPI/Swagger"
        if "actuator" in path_lower:
            return "Spring Actuator"
        if "application/json" in ct:
            return "REST"
        if "application/xml" in ct:
            return "SOAP/XML"
        return "REST"

    @staticmethod
    def _classify_by_path(path: str) -> str:
        path_lower = path.lower()
        if "graphql" in path_lower:
            return "GraphQL"
        if "swagger" in path_lower or "openapi" in path_lower:
            return "OpenAPI/Swagger"
        if "/v" in path_lower and re.search(r"/v\d+/", path_lower):
            return "REST (versioned)"
        return "REST"
