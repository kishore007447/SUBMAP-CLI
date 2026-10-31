"""Risk Classification Engine."""
from __future__ import annotations

from submap.core.models import (
    APIEndpoint,
    Confidence,
    Finding,
    JSFinding,
    LeakFinding,
    LiveHost,
    PortInfo,
    Severity,
    TLSInfo,
)
from submap.utils.logger import get_logger

log = get_logger(__name__)

# Leak types that warrant HIGH severity if confirmed
HIGH_LEAK_TYPES = {
    "env_file",
    "git_exposure",
    "backup_file",
    "config_file",
    "log_exposure",
    "source_map",
}

# Leak types that warrant MEDIUM severity
MEDIUM_LEAK_TYPES = {
    "debug_page",
    "api_docs_exposed",
    "server_metadata",
    "container_exposure",
    "directory_listing",
    "header_disclosure",
}

# Ports that are commonly interesting
RISKY_PORTS = {
    21: ("FTP", MEDIUM_LEAK_TYPES),      # FTP
    22: ("SSH", None),                   # SSH — INFO, usually expected
    23: ("Telnet", "HIGH"),              # Telnet — HIGH
    3306: ("MySQL", "HIGH"),             # MySQL exposed
    5432: ("PostgreSQL", "HIGH"),        # PostgreSQL exposed
    6379: ("Redis", "HIGH"),             # Redis exposed (no auth by default)
    27017: ("MongoDB", "HIGH"),          # MongoDB exposed
    9200: ("Elasticsearch", "HIGH"),     # Elasticsearch exposed
    4848: ("GlassFish Admin", "HIGH"),   # GlassFish admin
    7001: ("WebLogic", "HIGH"),          # WebLogic
    5900: ("VNC", "HIGH"),              # VNC
    1433: ("MSSQL", "HIGH"),            # MSSQL
    1521: ("Oracle DB", "HIGH"),         # Oracle DB
    2049: ("NFS", "MEDIUM"),            # NFS
    111: ("RPC", "MEDIUM"),             # RPC
    135: ("RPC/DCOM", "MEDIUM"),        # Windows RPC
    445: ("SMB", "HIGH"),              # SMB — often exploitable
    3389: ("RDP", "MEDIUM"),           # RDP exposed
}


class RiskClassifier:
    """Classify findings by severity and build Finding objects."""

    def classify_leaks(self, leaks: list[LeakFinding]) -> list[Finding]:
        findings: list[Finding] = []
        for leak in leaks:
            severity, confidence = self._classify_leak(leak)
            remediation = self._leak_remediation(leak.leak_type)
            findings.append(
                Finding(
                    asset=leak.hostname,
                    finding_type=f"leak:{leak.leak_type}",
                    category="Information Exposure",
                    severity=severity,
                    confidence=confidence,
                    evidence=f"{leak.url} — {leak.evidence}",
                    remediation=remediation,
                    extra={
                        "url": leak.url,
                        "leak_type": leak.leak_type,
                        "snippet": leak.content_snippet,
                        "status_code": leak.status_code,
                    },
                )
            )
        return findings

    def classify_ports(self, ports: list[PortInfo]) -> list[Finding]:
        findings: list[Finding] = []
        for port_info in ports:
            if port_info.port in RISKY_PORTS:
                service_name, risk = RISKY_PORTS[port_info.port]
                if risk == "HIGH":
                    severity = Severity.HIGH
                    confidence = Confidence.MEDIUM
                elif risk == "MEDIUM":
                    severity = Severity.MEDIUM
                    confidence = Confidence.MEDIUM
                else:
                    severity = Severity.LOW
                    confidence = Confidence.LOW

                findings.append(
                    Finding(
                        asset=f"{port_info.hostname}:{port_info.port}",
                        finding_type=f"open_port:{service_name}",
                        category="Service Exposure",
                        severity=severity,
                        confidence=confidence,
                        evidence=(
                            f"Port {port_info.port}/{port_info.protocol} open "
                            f"({service_name}) on {port_info.hostname}"
                        ),
                        remediation=self._port_remediation(port_info.port, service_name),
                        extra={
                            "port": port_info.port,
                            "service": service_name,
                            "version": port_info.version,
                        },
                    )
                )
        return findings

    def classify_tls(self, live_hosts: list[LiveHost]) -> list[Finding]:
        findings: list[Finding] = []
        for host in live_hosts:
            if host.tls_info is None:
                continue
            tls = host.tls_info
            if tls.is_expired:
                findings.append(
                    Finding(
                        asset=host.hostname,
                        finding_type="tls:expired_certificate",
                        category="TLS/Certificate",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"TLS certificate expired for {host.hostname}",
                        remediation="Renew the TLS certificate immediately.",
                        extra={"expires": str(tls.not_after)},
                    )
                )
            elif tls.days_until_expiry is not None and tls.days_until_expiry < 30:
                findings.append(
                    Finding(
                        asset=host.hostname,
                        finding_type="tls:expiring_soon",
                        category="TLS/Certificate",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Certificate expires in {tls.days_until_expiry} days",
                        remediation="Renew the TLS certificate before expiry.",
                        extra={"days_remaining": tls.days_until_expiry},
                    )
                )
            if tls.hostname_mismatch:
                findings.append(
                    Finding(
                        asset=host.hostname,
                        finding_type="tls:hostname_mismatch",
                        category="TLS/Certificate",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Certificate does not cover hostname {host.hostname}",
                        remediation="Use a certificate that covers this hostname.",
                    )
                )
        return findings

    def classify_js_findings(self, js_findings: list[JSFinding]) -> list[Finding]:
        findings: list[Finding] = []
        for jf in js_findings:
            if jf.hardcoded_secrets:
                for secret in jf.hardcoded_secrets:
                    findings.append(
                        Finding(
                            asset=jf.parent_hostname,
                            finding_type="js:hardcoded_secret",
                            category="Credential Exposure",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            evidence=(
                                f"{secret['type']} pattern detected in {jf.js_url} "
                                f"(redacted: {secret['redacted_value']})"
                            ),
                            remediation=(
                                "Remove hardcoded credentials from JavaScript. "
                                "Use environment variables and server-side configuration."
                            ),
                            extra={"js_url": jf.js_url, "secret_type": secret["type"]},
                        )
                    )
            if jf.has_source_map:
                findings.append(
                    Finding(
                        asset=jf.parent_hostname,
                        finding_type="js:source_map_exposed",
                        category="Information Exposure",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Source map exposed: {jf.source_map_url} in {jf.js_url}",
                        remediation="Remove source map references from production JavaScript.",
                        extra={"source_map_url": jf.source_map_url},
                    )
                )
        return findings

    def classify_headers(self, live_hosts: list[LiveHost]) -> list[Finding]:
        findings: list[Finding] = []
        for host in live_hosts:
            if host.security_headers is None:
                continue
            sh = host.security_headers
            missing = sh.missing_headers
            if missing:
                findings.append(
                    Finding(
                        asset=host.hostname,
                        finding_type="headers:missing_security_headers",
                        category="Security Configuration",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        evidence=f"Missing security headers: {', '.join(missing)}",
                        remediation=(
                            "Add missing security headers to HTTP responses: "
                            + ", ".join(missing)
                        ),
                        extra={"missing": missing},
                    )
                )
        return findings

    def classify_live_hosts(self, live_hosts: list[LiveHost]) -> list[Finding]:
        """Create LOW/INFO findings for all live hosts."""
        return [
            Finding(
                asset=host.hostname,
                finding_type="live_host",
                category="Asset Discovery",
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                evidence=f"Live host: {host.url} (HTTP {host.status_code})",
                remediation="",
                extra={
                    "title": host.title,
                    "server": host.server,
                    "technologies": host.technologies,
                    "cdn": host.cdn_provider,
                },
            )
            for host in live_hosts
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_leak(leak: LeakFinding) -> tuple[Severity, Confidence]:
        if leak.leak_type in HIGH_LEAK_TYPES:
            return Severity.HIGH, Confidence.CONFIRMED
        if leak.leak_type in MEDIUM_LEAK_TYPES:
            return Severity.MEDIUM, Confidence.HIGH
        return Severity.LOW, Confidence.MEDIUM

    @staticmethod
    def _leak_remediation(leak_type: str) -> str:
        REMEDIATIONS = {
            "env_file": "Restrict access to .env files via web server configuration. Never store secrets in .env committed to source control.",
            "git_exposure": "Block access to .git directory via web server. Remove sensitive data from git history using git-filter-branch or BFG Repo Cleaner.",
            "backup_file": "Remove backup files from public-facing servers. Store backups in secure, non-web-accessible locations.",
            "config_file": "Restrict access to configuration files. Move sensitive configuration out of the web root.",
            "debug_page": "Disable debug modes in production. Remove or restrict access to debugging interfaces.",
            "api_docs_exposed": "Restrict API documentation to authenticated users or internal networks only.",
            "directory_listing": "Disable directory listing in web server configuration.",
            "source_map": "Remove source map references from production builds.",
            "log_exposure": "Restrict access to log files. Store logs outside the web root.",
            "server_metadata": "Disable server status pages in production or restrict to internal IPs.",
            "container_exposure": "Do not expose container configuration files via web server.",
            "header_disclosure": "Configure web server to suppress or mask version information in response headers.",
        }
        return REMEDIATIONS.get(leak_type, "Review and restrict access to this resource.")

    @staticmethod
    def _port_remediation(port: int, service: str) -> str:
        if port in (3306, 5432, 6379, 27017, 9200, 1433, 1521):
            return (
                f"Database service ({service}) should not be exposed to the internet. "
                "Bind to localhost or restrict to specific trusted IPs using firewall rules."
            )
        if port == 22:
            return "Restrict SSH access to known IP ranges. Disable password auth; use key-based auth only."
        if port == 23:
            return "Disable Telnet immediately — use SSH instead. Telnet transmits data in cleartext."
        if port == 445:
            return "Restrict SMB access to internal networks only. Apply all recent security patches."
        if port == 3389:
            return "Restrict RDP access to VPN/trusted IPs only. Enable NLA and strong passwords."
        return f"Review whether {service} on port {port} needs to be publicly accessible."
