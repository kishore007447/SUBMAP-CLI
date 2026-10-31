"""Unit tests for SUBMAP core modules."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from submap.core.config import ScanConfig
from submap.core.models import (
    DNSRecord,
    DNSRecordType,
    DNSResult,
    Finding,
    LeakFinding,
    LiveHost,
    PortInfo,
    Severity,
    Confidence,
    Subdomain,
    ScanResult,
)
from submap.modules.risk_classifier import RiskClassifier
from submap.utils.validator import (
    is_private_ip,
    sanitize_url,
    validate_domain,
    validate_domain_list,
)


# ─── Validator tests ──────────────────────────────────────────────────────────

class TestValidator:
    def test_valid_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_valid_domain_with_subdomain(self):
        assert validate_domain("sub.example.com") == "sub.example.com"

    def test_valid_domain_strips_dot(self):
        assert validate_domain("example.com.") == "example.com"

    def test_invalid_domain_empty(self):
        assert validate_domain("") is None

    def test_invalid_domain_no_tld(self):
        assert validate_domain("example") is None

    def test_invalid_domain_ip(self):
        # IPs without TLDs are not valid domains
        result = validate_domain("192.168.1.1")
        assert result is None

    def test_invalid_metadata_host(self):
        assert validate_domain("169.254.169.254") is None

    def test_private_ip_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_private_ip_rfc1918_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_private_ip_rfc1918_192(self):
        assert is_private_ip("192.168.1.100") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_sanitize_url_valid(self):
        assert sanitize_url("https://example.com") == "https://example.com"

    def test_sanitize_url_localhost(self):
        assert sanitize_url("http://localhost/admin") is None

    def test_sanitize_url_metadata(self):
        assert sanitize_url("http://169.254.169.254/latest") is None

    def test_validate_domain_list(self, tmp_path: Path):
        f = tmp_path / "domains.txt"
        f.write_text("example.com\n# comment\ntest.org\ninvalid\n  \nexample.com\n")
        result = validate_domain_list(f)
        assert "example.com" in result
        assert "test.org" in result
        assert len(result) == 2  # deduplicated

    def test_validate_domain_list_missing_file(self, tmp_path: Path):
        result = validate_domain_list(tmp_path / "nonexistent.txt")
        assert result == []


# ─── Model tests ──────────────────────────────────────────────────────────────

class TestModels:
    def test_subdomain_hash(self):
        s1 = Subdomain(hostname="www.example.com", source="crt.sh")
        s2 = Subdomain(hostname="www.example.com", source="hackertarget")
        assert s1 == s2
        assert hash(s1) == hash(s2)

    def test_scan_result_update_stats(self):
        result = ScanResult(domain="example.com")
        result.subdomains = [
            Subdomain(hostname="a.example.com", resolved=True),
            Subdomain(hostname="b.example.com", resolved=False),
        ]
        result.live_hosts = [
            LiveHost(hostname="a.example.com", url="https://a.example.com", status_code=200)
        ]
        result.findings = [
            Finding(
                asset="a.example.com",
                finding_type="test",
                category="Test",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                evidence="test",
            ),
            Finding(
                asset="b.example.com",
                finding_type="test2",
                category="Test",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                evidence="test2",
            ),
        ]
        result.update_stats()
        assert result.total_subdomains == 2
        assert result.total_resolved == 1
        assert result.total_live == 1
        assert result.total_high == 1
        assert result.total_low == 1
        assert result.total_medium == 0

    def test_finding_id_generated(self):
        f = Finding(
            asset="example.com",
            finding_type="test",
            category="Test",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence="test",
        )
        assert f.finding_id
        assert len(f.finding_id) == 8

    def test_dns_result_default_unresolved(self):
        dr = DNSResult(hostname="example.com")
        assert dr.resolved is False
        assert dr.ip_addresses == []


# ─── Risk Classifier tests ────────────────────────────────────────────────────

class TestRiskClassifier:
    def setup_method(self):
        self.classifier = RiskClassifier()

    def test_classify_env_file_leak_high(self):
        leak = LeakFinding(
            url="https://example.com/.env",
            hostname="example.com",
            leak_type="env_file",
            evidence="HTTP 200 — content matched DB_",
            status_code=200,
        )
        findings = self.classifier.classify_leaks([leak])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].confidence == Confidence.CONFIRMED

    def test_classify_debug_page_medium(self):
        leak = LeakFinding(
            url="https://example.com/phpinfo.php",
            hostname="example.com",
            leak_type="debug_page",
            evidence="HTTP 200",
            status_code=200,
        )
        findings = self.classifier.classify_leaks([leak])
        assert findings[0].severity == Severity.MEDIUM

    def test_classify_mysql_port_high(self):
        port = PortInfo(hostname="db.example.com", ip_address="1.2.3.4", port=3306, protocol="tcp")
        findings = self.classifier.classify_ports([port])
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_classify_ssh_port_not_high(self):
        port = PortInfo(hostname="ssh.example.com", ip_address="1.2.3.4", port=22, protocol="tcp")
        findings = self.classifier.classify_ports([port])
        # SSH should be LOW/INFO, not HIGH
        assert all(f.severity != Severity.HIGH for f in findings)

    def test_classify_expired_tls_high(self):
        from datetime import datetime, timezone, timedelta
        from submap.core.models import TLSInfo

        tls = TLSInfo(
            is_expired=True,
            days_until_expiry=-5,
            not_after=datetime.now(timezone.utc) - timedelta(days=5),
            hostname_mismatch=False,
        )
        lh = LiveHost(
            hostname="example.com",
            url="https://example.com",
            status_code=200,
            tls_info=tls,
        )
        findings = self.classifier.classify_tls([lh])
        expired_findings = [f for f in findings if "expired" in f.finding_type]
        assert expired_findings
        assert expired_findings[0].severity == Severity.HIGH

    def test_missing_headers_low(self):
        from submap.core.models import SecurityHeaders
        sh = SecurityHeaders(
            hostname="example.com",
            missing_headers=["HSTS", "CSP", "X-Frame-Options"],
        )
        lh = LiveHost(
            hostname="example.com",
            url="https://example.com",
            status_code=200,
            security_headers=sh,
        )
        findings = self.classifier.classify_headers([lh])
        assert findings
        assert all(f.severity == Severity.LOW for f in findings)

    def test_live_host_classified_low(self):
        lh = LiveHost(
            hostname="example.com", url="https://example.com", status_code=200
        )
        findings = self.classifier.classify_live_hosts([lh])
        assert findings
        assert all(f.severity == Severity.LOW for f in findings)

    def test_empty_inputs_return_empty(self):
        assert self.classifier.classify_leaks([]) == []
        assert self.classifier.classify_ports([]) == []
        assert self.classifier.classify_tls([]) == []


# ─── Config tests ─────────────────────────────────────────────────────────────

class TestConfig:
    def test_config_defaults(self):
        cfg = ScanConfig(targets=["example.com"])
        assert cfg.passive is True
        assert cfg.active is False
        assert cfg.ports is False
        assert cfg.threads == 10
        assert cfg.timeout == 10

    def test_config_normalises_targets(self):
        cfg = ScanConfig(targets=["  EXAMPLE.COM  ", "TEST.ORG"])
        assert "example.com" in cfg.targets
        assert "test.org" in cfg.targets

    def test_config_invalid_empty_targets_removed(self):
        cfg = ScanConfig(targets=["  ", "example.com"])
        assert cfg.targets == ["example.com"]
