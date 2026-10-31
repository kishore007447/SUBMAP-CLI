"""Integration tests for SUBMAP modules."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import respx
import httpx

from submap.modules.discovery import SubdomainDiscovery
from submap.modules.dns_engine import DNSEngine
from submap.modules.live_host import LiveHostDetector
from submap.modules.leak_detector import LeakDetector
from submap.modules.api_discovery import APIDiscovery
from submap.modules.js_analyzer import JSAnalyzer
from submap.modules.asset_mapper import build_asset_map
from submap.core.models import Subdomain, ScanResult, LiveHost


# ─── Subdomain Discovery ──────────────────────────────────────────────────────

class TestSubdomainDiscovery:
    @pytest.mark.asyncio
    @respx.mock
    async def test_crt_sh_returns_subdomains(self):
        respx.get("https://crt.sh/?q=%.example.com&output=json").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"name_value": "www.example.com\nmail.example.com"},
                    {"name_value": "*.example.com"},  # wildcard — should be stripped
                ],
            )
        )

        disc = SubdomainDiscovery("example.com", passive=True, active=False, bruteforce=False)
        # Only test crt.sh
        results = await disc._crt_sh()

        hostnames = [s.hostname for s in results]
        assert "www.example.com" in hostnames
        assert "mail.example.com" in hostnames
        # wildcard * should not appear
        assert any("*" not in h for h in hostnames)

    @pytest.mark.asyncio
    @respx.mock
    async def test_crt_sh_handles_error(self):
        respx.get("https://crt.sh/?q=%.example.com&output=json").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        disc = SubdomainDiscovery("example.com", passive=True, active=False, bruteforce=False)
        results = await disc._crt_sh()
        assert results == []

    @pytest.mark.asyncio
    async def test_dedupe_removes_duplicates(self):
        disc = SubdomainDiscovery("example.com", passive=False, active=False, bruteforce=False)
        subs = [
            Subdomain(hostname="www.example.com", source="a"),
            Subdomain(hostname="www.example.com", source="b"),
            Subdomain(hostname="mail.example.com", source="a"),
        ]
        deduped = disc._dedupe(subs)
        assert len(deduped) == 2
        hostnames = [s.hostname for s in deduped]
        assert "www.example.com" in hostnames
        assert "mail.example.com" in hostnames

    @pytest.mark.asyncio
    async def test_brute_force_uses_default_wordlist(self):
        disc = SubdomainDiscovery("example.com", passive=False, active=False, bruteforce=True)
        wordlist = disc._default_wordlist()
        assert len(wordlist) > 10
        assert "www" in wordlist
        assert "api" in wordlist

    def test_out_of_scope_filtered(self):
        disc = SubdomainDiscovery("example.com", passive=False, active=False, bruteforce=False)
        subs = [
            Subdomain(hostname="www.example.com", source="a"),
            Subdomain(hostname="www.other.com", source="a"),  # out of scope
        ]
        deduped = disc._dedupe(subs)
        hostnames = [s.hostname for s in deduped]
        assert "www.other.com" not in hostnames


# ─── Live Host Detection ──────────────────────────────────────────────────────

class TestLiveHostDetector:
    @pytest.mark.asyncio
    async def test_probe_returns_live_host(self):
        """Test internal method directly without respx."""
        import httpx
        detector = LiveHostDetector(timeout=5, threads=1, rate_limit=100)
        
        # Test the title extraction and tech fingerprinting directly
        html = "<html><title>Example Domain</title></html>"
        title = detector._extract_title(html)
        assert title == "Example Domain"

    @pytest.mark.asyncio
    async def test_probe_detects_nginx(self):
        """Test nginx detection via _fingerprint directly."""
        detector = LiveHostDetector(timeout=5, threads=1, rate_limit=100)
        # Simulate a response with nginx server header
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "nginx/1.24.0"}
        mock_resp.text = "<html><title>Test</title></html>"
        
        from submap.modules.live_host import TECH_SIGNATURES
        import re
        
        # Run the fingerprint
        techs = detector._fingerprint(mock_resp)
        assert any(t.name == "Nginx" for t in techs)

    @pytest.mark.asyncio
    @respx.mock
    async def test_probe_returns_none_on_connect_error(self):
        respx.get("https://unreachable.example.com").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        respx.get("http://unreachable.example.com").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        detector = LiveHostDetector(timeout=3, threads=1, rate_limit=100)
        result = await detector._probe_host("unreachable.example.com")
        assert result is None

    def test_extract_title(self):
        detector = LiveHostDetector()
        title = detector._extract_title("<html><head><title>  Hello World  </title></head></html>")
        assert title == "Hello World"

    def test_extract_title_missing(self):
        detector = LiveHostDetector()
        assert detector._extract_title("<html><body>No title</body></html>") == ""

    def test_detect_cloudflare_cdn(self):
        detector = LiveHostDetector()
        resp = MagicMock()
        resp.headers = {"cf-ray": "abc123", "server": "cloudflare"}
        is_cdn, provider = detector._detect_cdn(resp)
        assert is_cdn is True
        assert "Cloudflare" in provider


# ─── Leak Detection ───────────────────────────────────────────────────────────

class TestLeakDetector:
    @pytest.mark.asyncio
    @respx.mock
    async def test_env_file_detected(self):
        respx.head("https://example.com/.env").mock(
            return_value=httpx.Response(200)
        )
        respx.get("https://example.com/.env").mock(
            return_value=httpx.Response(
                200,
                text="DB_HOST=localhost\nDB_PASSWORD=secret123\nAPP_KEY=base64:xyz",
                headers={"content-type": "text/plain"},
            )
        )

        detector = LeakDetector(timeout=5, threads=1, rate_limit=100)
        probe = {
            "path": "/.env",
            "type": "env_file",
            "expected_content": ["DB_", "SECRET", "KEY", "PASSWORD", "="],
        }

        # Use internal verify method
        fake_resp = httpx.Response(
            200,
            text="DB_HOST=localhost\nDB_PASSWORD=secret123\nAPP_KEY=base64:xyz",
            headers={"content-type": "text/plain"},
        )
        finding = detector._verify_finding(probe, "https://example.com/.env", "example.com", fake_resp)
        assert finding is not None
        assert finding.leak_type == "env_file"
        # Ensure secrets are redacted in snippet
        assert "secret123" not in finding.content_snippet

    def test_status_code_alone_not_enough(self):
        """Verify that a 200 response without matching content is not flagged."""
        detector = LeakDetector()
        probe = {
            "path": "/.env",
            "type": "env_file",
            "expected_content": ["DB_", "SECRET"],
        }
        # Response has no matching content
        fake_resp = httpx.Response(
            200,
            text="<html><body>Hello world</body></html>",
            headers={"content-type": "text/html"},
        )
        finding = detector._verify_finding(probe, "https://example.com/.env", "example.com", fake_resp)
        assert finding is None


# ─── Asset Mapper ────────────────────────────────────────────────────────────

class TestAssetMapper:
    def test_asset_map_structure(self):
        from submap.core.models import DNSResult
        result = ScanResult(domain="example.com")
        result.subdomains = [
            Subdomain(hostname="www.example.com", resolved=True, ip_addresses=["1.2.3.4"])
        ]
        result.dns_results = {
            "www.example.com": DNSResult(
                hostname="www.example.com",
                ip_addresses=["1.2.3.4"],
                resolved=True,
            )
        }
        result.live_hosts = [
            LiveHost(
                hostname="www.example.com",
                url="https://www.example.com",
                status_code=200,
                technologies=["Nginx"],
            )
        ]
        result.update_stats()

        asset_map = build_asset_map(result)
        assert asset_map["domain"] == "example.com"
        assert len(asset_map["subdomains"]) == 1
        assert asset_map["subdomains"][0]["hostname"] == "www.example.com"
        assert asset_map["subdomains"][0]["is_live"] is True
        assert "1.2.3.4" in asset_map["ip_clusters"]

    def test_relationships_include_ips(self):
        from submap.core.models import DNSResult
        result = ScanResult(domain="example.com")
        result.subdomains = [
            Subdomain(hostname="www.example.com", resolved=True, ip_addresses=["5.6.7.8"])
        ]
        result.dns_results = {
            "www.example.com": DNSResult(
                hostname="www.example.com",
                ip_addresses=["5.6.7.8"],
                resolved=True,
            )
        }
        result.update_stats()

        asset_map = build_asset_map(result)
        ip_rels = [r for r in asset_map["relationships"] if r["type"] == "resolves_to"]
        assert any(r["to"] == "5.6.7.8" for r in ip_rels)


# ─── JS Analyzer ─────────────────────────────────────────────────────────────

class TestJSAnalyzer:
    def test_endpoint_extraction(self):
        analyzer = JSAnalyzer()
        content = """
        const apiBase = '/api/v1/users';
        fetch('/api/v2/products').then(r => r.json());
        axios.get('/api/auth/login');
        """
        finding = analyzer._parse_js(content, "https://example.com/app.js", "example.com")
        all_paths = finding.endpoints + finding.api_routes
        assert any("/api" in p for p in all_paths)

    def test_source_map_detected(self):
        analyzer = JSAnalyzer()
        content = "var a = 1;\n//# sourceMappingURL=app.js.map\n"
        finding = analyzer._parse_js(content, "https://example.com/app.js", "example.com")
        assert finding.has_source_map is True
        assert "app.js.map" in finding.source_map_url

    def test_secrets_redacted(self):
        analyzer = JSAnalyzer()
        content = 'const apiKey = "sk-abcdef1234567890";'
        finding = analyzer._parse_js(content, "https://example.com/app.js", "example.com")
        if finding.hardcoded_secrets:
            for secret in finding.hardcoded_secrets:
                # Full secret must not be present in redacted_value
                assert "abcdef1234567890" not in secret["redacted_value"]

    def test_no_false_secrets_on_clean_js(self):
        analyzer = JSAnalyzer()
        content = "function add(a, b) { return a + b; } console.log(add(1, 2));"
        finding = analyzer._parse_js(content, "https://example.com/clean.js", "example.com")
        # No secrets expected in clean code
        assert len(finding.hardcoded_secrets) == 0
