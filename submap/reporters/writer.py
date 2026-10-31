"""Output reporters: TXT, JSON, CSV, Markdown, HTML."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, BaseLoader

from submap.core.models import ScanResult, Severity
from submap.modules.asset_mapper import build_asset_map
from submap.utils.logger import get_logger

log = get_logger(__name__)

# ─── HTML Report Template ─────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SUBMAP Report — {{ result.domain }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
  .header { background: linear-gradient(135deg, #161b22, #21262d); padding: 2rem; border-bottom: 1px solid #30363d; }
  .logo { font-family: monospace; color: #58a6ff; font-size: 1.4rem; font-weight: bold; }
  .domain { color: #f0883e; font-size: 1.8rem; margin-top: 0.5rem; }
  .meta { color: #8b949e; margin-top: 0.5rem; font-size: 0.9rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 2rem 0; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; text-align: center; }
  .stat-number { font-size: 2rem; font-weight: bold; }
  .stat-label { color: #8b949e; font-size: 0.85rem; margin-top: 0.3rem; }
  .high { color: #f85149; }
  .medium { color: #f0883e; }
  .low { color: #58a6ff; }
  .info { color: #3fb950; }
  .section { margin: 2rem 0; }
  .section-title { font-size: 1.2rem; color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { background: #21262d; color: #8b949e; padding: 0.6rem 1rem; text-align: left; font-weight: 600; }
  td { padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; }
  tr:hover { background: #161b22; }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .badge-high { background: #3d1a1a; color: #f85149; }
  .badge-medium { background: #3d2a1a; color: #f0883e; }
  .badge-low { background: #1a2a3d; color: #58a6ff; }
  .badge-info { background: #1a3d1a; color: #3fb950; }
  .footer { text-align: center; color: #8b949e; padding: 2rem; font-size: 0.85rem; border-top: 1px solid #30363d; }
  code { font-family: monospace; background: #21262d; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="header">
  <div class="logo">SUBMAP — Advanced Subdomain Discovery & Attack Surface Mapping</div>
  <div class="domain">{{ result.domain }}</div>
  <div class="meta">
    Scan ID: {{ result.scan_id }} &nbsp;|&nbsp;
    Started: {{ result.started_at.strftime('%Y-%m-%d %H:%M UTC') if result.started_at else 'N/A' }} &nbsp;|&nbsp;
    Finished: {{ result.finished_at.strftime('%Y-%m-%d %H:%M UTC') if result.finished_at else 'N/A' }} &nbsp;|&nbsp;
    Author: Kishore Baskaran (0xk1sh0re)
  </div>
</div>
<div class="container">

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-number info">{{ result.total_subdomains }}</div><div class="stat-label">Subdomains</div></div>
    <div class="stat-card"><div class="stat-number info">{{ result.total_resolved }}</div><div class="stat-label">Resolved</div></div>
    <div class="stat-card"><div class="stat-number info">{{ result.total_live }}</div><div class="stat-label">Live Hosts</div></div>
    <div class="stat-card"><div class="stat-number info">{{ result.total_apis }}</div><div class="stat-label">API Endpoints</div></div>
    <div class="stat-card"><div class="stat-number high">{{ result.total_high }}</div><div class="stat-label">HIGH</div></div>
    <div class="stat-card"><div class="stat-number medium">{{ result.total_medium }}</div><div class="stat-label">MEDIUM</div></div>
    <div class="stat-card"><div class="stat-number low">{{ result.total_low }}</div><div class="stat-label">LOW</div></div>
  </div>

  <!-- Findings -->
  <div class="section">
    <div class="section-title">🔴 Findings</div>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Asset</th><th>Type</th><th>Evidence</th></tr></thead>
      <tbody>
        {% for f in result.findings %}
        <tr>
          <td><code>{{ f.finding_id }}</code></td>
          <td><span class="badge badge-{{ f.severity.value.lower() }}">{{ f.severity.value }}</span></td>
          <td><code>{{ f.asset }}</code></td>
          <td>{{ f.finding_type }}</td>
          <td>{{ f.evidence[:120] }}</td>
        </tr>
        {% endfor %}
        {% if not result.findings %}<tr><td colspan="5" style="text-align:center;color:#8b949e">No findings</td></tr>{% endif %}
      </tbody>
    </table>
  </div>

  <!-- Live Hosts -->
  <div class="section">
    <div class="section-title">🟢 Live Hosts ({{ result.live_hosts | length }})</div>
    <table>
      <thead><tr><th>Hostname</th><th>Status</th><th>Title</th><th>Technologies</th><th>Response (ms)</th></tr></thead>
      <tbody>
        {% for h in result.live_hosts %}
        <tr>
          <td><a href="{{ h.url }}" style="color:#58a6ff">{{ h.hostname }}</a></td>
          <td>{{ h.status_code }}</td>
          <td>{{ h.title[:60] }}</td>
          <td>{{ h.technologies[:3] | join(', ') }}</td>
          <td>{{ h.response_time_ms | int }}</td>
        </tr>
        {% endfor %}
        {% if not result.live_hosts %}<tr><td colspan="5" style="text-align:center;color:#8b949e">None detected</td></tr>{% endif %}
      </tbody>
    </table>
  </div>

  <!-- Subdomains -->
  <div class="section">
    <div class="section-title">🌐 Subdomains ({{ result.subdomains | length }})</div>
    <table>
      <thead><tr><th>Hostname</th><th>Source</th><th>Resolved</th><th>IPs</th></tr></thead>
      <tbody>
        {% for s in result.subdomains %}
        <tr>
          <td><code>{{ s.hostname }}</code></td>
          <td>{{ s.source }}</td>
          <td>{{ '✓' if s.resolved else '–' }}</td>
          <td>{{ s.ip_addresses[:2] | join(', ') }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- API Endpoints -->
  {% if result.api_endpoints %}
  <div class="section">
    <div class="section-title">🔌 API Endpoints ({{ result.api_endpoints | length }})</div>
    <table>
      <thead><tr><th>URL</th><th>Type</th><th>Status</th><th>Source</th></tr></thead>
      <tbody>
        {% for ep in result.api_endpoints %}
        <tr>
          <td><code>{{ ep.url[:80] }}</code></td>
          <td>{{ ep.api_type }}</td>
          <td>{{ ep.status_code }}</td>
          <td>{{ ep.source }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

</div>
<div class="footer">
  Generated by SUBMAP v1.0.0 — by Kishore Baskaran (0xk1sh0re) &nbsp;|&nbsp;
  {{ now.strftime('%Y-%m-%d %H:%M UTC') }}
  <br><small>This report is intended for authorized security testing only.</small>
</div>
</body>
</html>
"""

MD_TEMPLATE = """# SUBMAP Report — {{ result.domain }}

**Scan ID:** `{{ result.scan_id }}`
**Started:** {{ result.started_at.strftime('%Y-%m-%d %H:%M UTC') if result.started_at else 'N/A' }}
**Finished:** {{ result.finished_at.strftime('%Y-%m-%d %H:%M UTC') if result.finished_at else 'N/A' }}
**Author:** Kishore Baskaran (0xk1sh0re)

---

## Summary

| Metric | Count |
|--------|-------|
| Subdomains | {{ result.total_subdomains }} |
| Resolved | {{ result.total_resolved }} |
| Live Hosts | {{ result.total_live }} |
| API Endpoints | {{ result.total_apis }} |
| 🔴 HIGH | {{ result.total_high }} |
| 🟠 MEDIUM | {{ result.total_medium }} |
| 🔵 LOW | {{ result.total_low }} |

---

## Findings

{% for f in result.findings %}
### [{{ f.severity.value }}] {{ f.finding_type }} — `{{ f.asset }}`
- **ID:** `{{ f.finding_id }}`
- **Category:** {{ f.category }}
- **Confidence:** {{ f.confidence.value }}
- **Evidence:** {{ f.evidence }}
- **Remediation:** {{ f.remediation }}
- **Detected:** {{ f.detected_at.strftime('%Y-%m-%d %H:%M UTC') }}

{% endfor %}
{% if not result.findings %}
*No significant findings.*
{% endif %}

---

## Live Hosts

| Hostname | Status | Title | Technologies |
|----------|--------|-------|--------------|
{% for h in result.live_hosts %}
| `{{ h.hostname }}` | {{ h.status_code }} | {{ h.title[:50] }} | {{ h.technologies[:3] | join(', ') }} |
{% endfor %}

---

## Subdomains

{% for s in result.subdomains %}
- `{{ s.hostname }}` ({{ s.source }}){% if s.resolved %} ✓ `{{ s.ip_addresses[:1] | join('') }}`{% endif %}
{% endfor %}

---

*Generated by SUBMAP v1.0.0 — for authorized use only.*
"""


class ReportWriter:
    """Write scan results to all output formats."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.jinja = Environment(loader=BaseLoader(), autoescape=False)

    def write_all(self, result: ScanResult, asset_map: dict) -> None:
        """Write all output files."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._write_subdomains(result)
        self._write_resolved(result)
        self._write_live_hosts(result)
        self._write_dns_records(result)
        self._write_ports(result)
        self._write_technologies(result)
        self._write_api_endpoints(result)
        self._write_urls(result)
        self._write_js_findings(result)
        self._write_leaks(result)
        self._write_findings_by_severity(result)
        self._write_findings_json(result)
        self._write_asset_map(asset_map)
        self._write_csv(result)
        self._write_markdown(result)
        self._write_html(result)
        self._write_summary(result)

    # ── Plain text files ──────────────────────────────────────────────────────

    def _write_subdomains(self, result: ScanResult) -> None:
        path = self.output_dir / "subdomains.txt"
        path.write_text("\n".join(s.hostname for s in result.subdomains), encoding="utf-8")

    def _write_resolved(self, result: ScanResult) -> None:
        path = self.output_dir / "resolved.txt"
        resolved = [s.hostname for s in result.subdomains if s.resolved]
        path.write_text("\n".join(resolved), encoding="utf-8")

    def _write_live_hosts(self, result: ScanResult) -> None:
        path = self.output_dir / "live_hosts.txt"
        path.write_text("\n".join(h.url for h in result.live_hosts), encoding="utf-8")

    def _write_api_endpoints(self, result: ScanResult) -> None:
        path = self.output_dir / "api_endpoints.txt"
        path.write_text("\n".join(ep.url for ep in result.api_endpoints), encoding="utf-8")

    def _write_urls(self, result: ScanResult) -> None:
        path = self.output_dir / "urls.txt"
        path.write_text("\n".join(u.url for u in result.urls), encoding="utf-8")

    def _write_findings_by_severity(self, result: ScanResult) -> None:
        for sev in ("HIGH", "MEDIUM", "LOW"):
            path = self.output_dir / f"{sev.lower()}.txt"
            lines = [
                f"[{f.finding_id}] {f.asset} — {f.finding_type}\n  {f.evidence}"
                for f in result.findings
                if f.severity.value == sev
            ]
            path.write_text("\n\n".join(lines), encoding="utf-8")

    # ── JSON files ────────────────────────────────────────────────────────────

    def _write_dns_records(self, result: ScanResult) -> None:
        path = self.output_dir / "dns_records.json"
        data = {
            h: dns_r.model_dump(mode="json")
            for h, dns_r in result.dns_results.items()
        }
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _write_ports(self, result: ScanResult) -> None:
        path = self.output_dir / "ports.json"
        path.write_text(
            json.dumps([p.model_dump(mode="json") for p in result.ports], indent=2),
            encoding="utf-8",
        )

    def _write_technologies(self, result: ScanResult) -> None:
        path = self.output_dir / "technologies.json"
        data = {
            h: [t.model_dump(mode="json") for t in techs]
            for h, techs in result.technologies.items()
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _write_js_findings(self, result: ScanResult) -> None:
        path = self.output_dir / "javascript_findings.json"
        path.write_text(
            json.dumps([j.model_dump(mode="json") for j in result.js_findings], indent=2),
            encoding="utf-8",
        )

    def _write_leaks(self, result: ScanResult) -> None:
        path = self.output_dir / "information_leaks.json"
        path.write_text(
            json.dumps([l.model_dump(mode="json") for l in result.leaks], indent=2),
            encoding="utf-8",
        )

    def _write_findings_json(self, result: ScanResult) -> None:
        path = self.output_dir / "findings.json"
        path.write_text(
            json.dumps([f.model_dump(mode="json") for f in result.findings], indent=2, default=str),
            encoding="utf-8",
        )

    def _write_asset_map(self, asset_map: dict) -> None:
        path = self.output_dir / "asset_map.json"
        path.write_text(json.dumps(asset_map, indent=2, default=str), encoding="utf-8")

    # ── Structured formats ────────────────────────────────────────────────────

    def _write_csv(self, result: ScanResult) -> None:
        path = self.output_dir / "report.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "finding_id", "severity", "confidence", "asset",
                    "finding_type", "category", "evidence", "remediation",
                    "detected_at",
                ],
            )
            writer.writeheader()
            for finding in result.findings:
                writer.writerow(
                    {
                        "finding_id": finding.finding_id,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence.value,
                        "asset": finding.asset,
                        "finding_type": finding.finding_type,
                        "category": finding.category,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "detected_at": finding.detected_at.isoformat(),
                    }
                )

    def _write_markdown(self, result: ScanResult) -> None:
        path = self.output_dir / "report.md"
        tmpl = self.jinja.from_string(MD_TEMPLATE)
        path.write_text(
            tmpl.render(result=result, now=datetime.utcnow()),
            encoding="utf-8",
        )

    def _write_html(self, result: ScanResult) -> None:
        path = self.output_dir / "report.html"
        tmpl = self.jinja.from_string(HTML_TEMPLATE)
        path.write_text(
            tmpl.render(result=result, now=datetime.utcnow()),
            encoding="utf-8",
        )

    def _write_summary(self, result: ScanResult) -> None:
        path = self.output_dir / "scan_summary.txt"
        duration = "N/A"
        if result.started_at and result.finished_at:
            delta = result.finished_at - result.started_at
            duration = f"{int(delta.total_seconds())}s"

        lines = [
            "═" * 60,
            "  SUBMAP Scan Summary",
            "═" * 60,
            f"  Domain       : {result.domain}",
            f"  Scan ID      : {result.scan_id}",
            f"  Started      : {result.started_at}",
            f"  Finished     : {result.finished_at}",
            f"  Duration     : {duration}",
            "─" * 60,
            f"  Subdomains   : {result.total_subdomains}",
            f"  Resolved     : {result.total_resolved}",
            f"  Live Hosts   : {result.total_live}",
            f"  API Endpoints: {result.total_apis}",
            f"  URLs         : {result.total_urls}",
            "─" * 60,
            f"  HIGH         : {result.total_high}",
            f"  MEDIUM       : {result.total_medium}",
            f"  LOW          : {result.total_low}",
            "═" * 60,
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
