"""Pydantic models for all SUBMAP findings and data structures."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DNSRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    CAA = "CAA"
    PTR = "PTR"
    SOA = "SOA"


# ─── Core data models ─────────────────────────────────────────────────────────

class Subdomain(BaseModel):
    """A discovered subdomain."""
    hostname: str
    source: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    cname: Optional[str] = None
    resolved: bool = False
    wildcard: bool = False
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    def __hash__(self) -> int:
        return hash(self.hostname)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Subdomain):
            return self.hostname == other.hostname
        return False


class DNSRecord(BaseModel):
    """A DNS record."""
    hostname: str
    record_type: DNSRecordType
    value: str
    ttl: int = 0


class DNSResult(BaseModel):
    """Full DNS intelligence for a hostname."""
    hostname: str
    records: list[DNSRecord] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    caa_records: list[str] = Field(default_factory=list)
    ptr_records: list[str] = Field(default_factory=list)
    is_wildcard: bool = False
    resolved: bool = False


class TLSInfo(BaseModel):
    """TLS certificate information."""
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    sans: list[str] = Field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_expired: bool = False
    days_until_expiry: Optional[int] = None
    hostname_mismatch: bool = False
    tls_version: str = ""
    cipher_suite: str = ""
    serial_number: str = ""


class SecurityHeaders(BaseModel):
    """HTTP security headers analysis."""
    hostname: str
    hsts: Optional[str] = None
    csp: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_frame_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    x_xss_protection: Optional[str] = None
    missing_headers: list[str] = Field(default_factory=list)


class LiveHost(BaseModel):
    """A detected live web host."""
    hostname: str
    url: str
    status_code: int
    title: str = ""
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    response_time_ms: float = 0.0
    server: str = ""
    ip_address: str = ""
    content_length: int = 0
    technologies: list[str] = Field(default_factory=list)
    tls_info: Optional[TLSInfo] = None
    security_headers: Optional[SecurityHeaders] = None
    is_cdn: bool = False
    cdn_provider: str = ""
    webserver: str = ""


class Technology(BaseModel):
    """A detected web technology."""
    name: str
    version: str = ""
    category: str = ""
    evidence: str = ""


class PortInfo(BaseModel):
    """A discovered open port."""
    hostname: str
    ip_address: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class APIEndpoint(BaseModel):
    """A discovered API endpoint."""
    url: str
    method: str = "GET"
    source: str = ""
    api_type: str = ""           # REST, GraphQL, SOAP …
    path: str = ""
    parameters: list[str] = Field(default_factory=list)
    requires_auth: bool = False
    status_code: int = 0
    content_type: str = ""
    is_documented: bool = False
    parent_hostname: str = ""


class JSFinding(BaseModel):
    """A finding extracted from JavaScript analysis."""
    js_url: str
    parent_hostname: str
    endpoints: list[str] = Field(default_factory=list)
    api_routes: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    has_source_map: bool = False
    source_map_url: str = ""
    suspicious_patterns: list[dict[str, str]] = Field(default_factory=list)
    hardcoded_secrets: list[dict[str, str]] = Field(default_factory=list)


class URLRecord(BaseModel):
    """A crawled or historically discovered URL."""
    url: str
    source: str = ""
    status_code: int = 0
    content_type: str = ""
    parameters: list[str] = Field(default_factory=list)
    extension: str = ""
    is_interesting: bool = False
    category: str = ""


class LeakFinding(BaseModel):
    """An information exposure / leak finding."""
    url: str
    hostname: str
    leak_type: str
    evidence: str = ""
    status_code: int = 0
    content_type: str = ""
    content_snippet: str = ""
    redacted: bool = True


# ─── Risk finding ─────────────────────────────────────────────────────────────

class Finding(BaseModel):
    """A classified security / recon finding."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    asset: str
    finding_type: str
    category: str
    severity: Severity
    confidence: Confidence
    evidence: str
    remediation: str = ""
    false_positive: bool = False
    severity_override: Optional[Severity] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    extra: dict[str, Any] = Field(default_factory=dict)


# ─── Scan results container ────────────────────────────────────────────────────

class ScanResult(BaseModel):
    """Aggregated results for a single domain scan."""
    domain: str
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    subdomains: list[Subdomain] = Field(default_factory=list)
    dns_results: dict[str, DNSResult] = Field(default_factory=dict)
    live_hosts: list[LiveHost] = Field(default_factory=list)
    ports: list[PortInfo] = Field(default_factory=list)
    technologies: dict[str, list[Technology]] = Field(default_factory=dict)
    api_endpoints: list[APIEndpoint] = Field(default_factory=list)
    js_findings: list[JSFinding] = Field(default_factory=list)
    urls: list[URLRecord] = Field(default_factory=list)
    leaks: list[LeakFinding] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    # stats
    total_subdomains: int = 0
    total_resolved: int = 0
    total_live: int = 0
    total_apis: int = 0
    total_urls: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0

    def update_stats(self) -> None:
        self.total_subdomains = len(self.subdomains)
        self.total_resolved = sum(1 for s in self.subdomains if s.resolved)
        self.total_live = len(self.live_hosts)
        self.total_apis = len(self.api_endpoints)
        self.total_urls = len(self.urls)
        self.total_high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.total_medium = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.total_low = sum(1 for f in self.findings if f.severity == Severity.LOW)
