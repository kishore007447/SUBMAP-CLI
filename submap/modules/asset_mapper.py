"""Asset Mapping — build relationship graph between all discovered assets."""
from __future__ import annotations

from submap.core.models import ScanResult
from submap.utils.logger import get_logger

log = get_logger(__name__)


def build_asset_map(result: ScanResult) -> dict:
    """Build a JSON-serialisable asset relationship map."""
    asset_map: dict = {
        "domain": result.domain,
        "scan_id": result.scan_id,
        "subdomains": [],
        "ip_clusters": {},
        "relationships": [],
        "statistics": {
            "total_subdomains": result.total_subdomains,
            "total_resolved": result.total_resolved,
            "total_live": result.total_live,
            "total_apis": result.total_apis,
            "total_urls": result.total_urls,
            "total_findings": len(result.findings),
            "high": result.total_high,
            "medium": result.total_medium,
            "low": result.total_low,
        },
    }

    # Build subdomain nodes
    live_hostnames = {h.hostname for h in result.live_hosts}
    hostname_to_ips: dict[str, list[str]] = {}
    for dns_r in result.dns_results.values():
        hostname_to_ips[dns_r.hostname] = dns_r.ip_addresses

    for sub in result.subdomains:
        # Use DNS results first, fall back to subdomain's own ip_addresses list
        ips = hostname_to_ips.get(sub.hostname, sub.ip_addresses)
        node = {
            "hostname": sub.hostname,
            "source": sub.source,
            "resolved": sub.resolved,
            "wildcard": sub.wildcard,
            "ip_addresses": ips,
            "is_live": sub.hostname in live_hostnames,
        }
        # Attach technologies if live
        if sub.hostname in live_hostnames:
            lh = next((h for h in result.live_hosts if h.hostname == sub.hostname), None)
            if lh:
                node["title"] = lh.title
                node["status_code"] = lh.status_code
                node["technologies"] = lh.technologies
                node["cdn"] = lh.cdn_provider

        # Attach DNS info
        dns_r = result.dns_results.get(sub.hostname)
        if dns_r:
            node["cname_chain"] = dns_r.cname_chain
            node["mx_records"] = dns_r.mx_records
            node["ns_records"] = dns_r.ns_records

        asset_map["subdomains"].append(node)

        # Relationships: subdomain → IPs
        for ip in ips:
            asset_map["relationships"].append(
                {"from": sub.hostname, "to": ip, "type": "resolves_to"}
            )
            # IP cluster
            if ip not in asset_map["ip_clusters"]:
                asset_map["ip_clusters"][ip] = []
            if sub.hostname not in asset_map["ip_clusters"][ip]:
                asset_map["ip_clusters"][ip].append(sub.hostname)

    # API endpoint relationships
    for ep in result.api_endpoints:
        asset_map["relationships"].append(
            {
                "from": ep.parent_hostname,
                "to": ep.url,
                "type": "exposes_api",
                "api_type": ep.api_type,
            }
        )

    # Leak relationships
    for leak in result.leaks:
        asset_map["relationships"].append(
            {
                "from": leak.hostname,
                "to": leak.url,
                "type": "information_exposure",
                "leak_type": leak.leak_type,
            }
        )

    return asset_map


def render_terminal_map(result: ScanResult) -> str:
    """Render a simple hierarchical terminal asset map."""
    lines = [f"  [root] {result.domain}"]

    live_set = {h.hostname for h in result.live_hosts}
    dns_map = result.dns_results

    for sub in result.subdomains:
        icon = "🟢" if sub.hostname in live_set else "⚪"
        dns_r = dns_map.get(sub.hostname)
        ips = dns_r.ip_addresses if dns_r else []
        ip_str = f" → {', '.join(ips[:2])}" if ips else ""
        lines.append(f"  ├── {icon} {sub.hostname}{ip_str}")

        # Nested: technologies
        if sub.hostname in live_set:
            lh = next((h for h in result.live_hosts if h.hostname == sub.hostname), None)
            if lh and lh.technologies:
                lines.append(f"  │   └── 🔧 {', '.join(lh.technologies[:4])}")

    # API endpoints summary
    if result.api_endpoints:
        lines.append(f"\n  [APIs] {len(result.api_endpoints)} discovered")
        for ep in result.api_endpoints[:5]:
            lines.append(f"  ├── {ep.api_type}: {ep.url}")
        if len(result.api_endpoints) > 5:
            lines.append(f"  └── ... and {len(result.api_endpoints) - 5} more")

    return "\n".join(lines)
