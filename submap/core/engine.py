"""The main scan orchestration engine."""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from submap.core.config import ScanConfig
from submap.core.models import ScanResult, Severity
from submap.db.storage import ScanDatabase
from submap.modules.api_discovery import APIDiscovery
from submap.modules.asset_mapper import build_asset_map, render_terminal_map
from submap.modules.discovery import SubdomainDiscovery
from submap.modules.dns_engine import DNSEngine
from submap.modules.js_analyzer import JSAnalyzer
from submap.modules.leak_detector import LeakDetector
from submap.modules.live_host import LiveHostDetector
from submap.modules.port_scanner import PortScanner
from submap.modules.risk_classifier import RiskClassifier
from submap.modules.url_recon import URLRecon
from submap.reporters.writer import ReportWriter
from submap.utils.logger import configure_logging, get_logger

log = get_logger(__name__)


class ScanEngine:
    """Orchestrates the full SUBMAP scan pipeline."""

    def __init__(self, config: ScanConfig, console: Console) -> None:
        self.config = config
        self.console = console
        self.db = ScanDatabase()
        configure_logging(config.verbose, config.silent)

    async def run(self) -> None:
        """Run scans for all targets."""
        for domain in self.config.targets:
            await self._scan_domain(domain)

    async def _scan_domain(self, domain: str) -> None:
        cfg = self.config
        result = ScanResult(domain=domain, started_at=datetime.utcnow())
        self.db.save_scan_start(result.scan_id, domain, cfg.model_dump(mode="json", exclude_none=True))

        # Set up output directory
        output_dir: Optional[Path] = None
        if cfg.save and cfg.output_dir:
            output_dir = cfg.output_dir / domain
            output_dir.mkdir(parents=True, exist_ok=True)

        if not cfg.silent:
            self.console.print(
                Panel(
                    f"[bold cyan]Target:[/] [bold white]{domain}[/]\n"
                    f"[dim]Passive:[/] {'✓' if cfg.passive else '✗'}  "
                    f"[dim]Active:[/] {'✓' if cfg.active else '✗'}  "
                    f"[dim]Bruteforce:[/] {'✓' if cfg.bruteforce else '✗'}  "
                    f"[dim]Ports:[/] {'✓' if cfg.ports else '✗'}  "
                    f"[dim]API:[/] {'✓' if cfg.api else '✗'}  "
                    f"[dim]Leaks:[/] {'✓' if cfg.leaks else '✗'}",
                    title="[bold cyan]SUBMAP[/]",
                    border_style="cyan",
                )
            )

        # Build progress display
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )

        with progress:
            # ── STAGE 1: Subdomain Discovery ─────────────────────────────────
            task_disc = progress.add_task("[bold]Subdomain Discovery", total=None)
            discoverer = SubdomainDiscovery(
                domain=domain,
                passive=cfg.passive,
                active=cfg.active,
                bruteforce=cfg.bruteforce,
                recursive=cfg.recursive,
                wordlist=cfg.wordlist,
                resolvers=cfg.resolvers,
                threads=cfg.threads,
                timeout=cfg.timeout,
                rate_limit=cfg.rate_limit,
                verbose=cfg.verbose,
            )
            subdomains = await discoverer.discover()
            # Apply exclusions
            excluded = set(cfg.exclude)
            subdomains = [s for s in subdomains if s.hostname not in excluded]
            # Apply include filter
            if cfg.include:
                subdomains = [
                    s for s in subdomains
                    if any(pattern in s.hostname for pattern in cfg.include)
                ]
            result.subdomains = subdomains
            progress.update(task_disc, completed=True, total=1, description=f"[bold]Subdomain Discovery ({len(subdomains)} found)")
            self._status(f"Discovered [bold cyan]{len(subdomains)}[/] subdomains")

            # ── STAGE 2: DNS Resolution ───────────────────────────────────────
            if cfg.dns and subdomains:
                task_dns = progress.add_task("[bold]DNS Resolution", total=len(subdomains))
                resolver_list = None
                if cfg.resolvers and cfg.resolvers.exists():
                    resolver_list = [l.strip() for l in cfg.resolvers.read_text().splitlines() if l.strip()]

                dns_engine = DNSEngine(
                    resolvers=resolver_list,
                    timeout=cfg.timeout,
                    threads=cfg.threads,
                )
                hostnames = [s.hostname for s in subdomains]
                dns_results = await dns_engine.resolve_all(hostnames, domain)
                result.dns_results = dns_results

                # Update subdomains with resolution data
                for sub in result.subdomains:
                    dr = dns_results.get(sub.hostname)
                    if dr:
                        sub.ip_addresses = dr.ip_addresses
                        sub.resolved = dr.resolved
                        sub.wildcard = dr.is_wildcard
                        if dr.cname_chain:
                            sub.cname = dr.cname_chain[0]

                resolved_count = sum(1 for s in result.subdomains if s.resolved)
                progress.update(task_dns, completed=len(subdomains), description=f"[bold]DNS Resolution ({resolved_count} resolved)")
                self._status(f"Resolved [bold cyan]{resolved_count}[/] hosts")

            # ── STAGE 3: Live Host Detection ──────────────────────────────────
            if cfg.live:
                resolved_hosts = [s.hostname for s in result.subdomains if s.resolved]
                if not resolved_hosts:
                    resolved_hosts = [s.hostname for s in result.subdomains]

                task_live = progress.add_task("[bold]Live Host Detection", total=len(resolved_hosts))
                detector = LiveHostDetector(
                    timeout=cfg.timeout,
                    retries=cfg.retries,
                    threads=cfg.threads,
                    rate_limit=cfg.rate_limit,
                    proxy=cfg.proxy,
                    verbose=cfg.verbose,
                )
                live_hosts = await detector.probe_all(resolved_hosts)
                result.live_hosts = live_hosts

                # Collect technologies
                for lh in live_hosts:
                    if lh.technologies:
                        from submap.modules.live_host import TECH_SIGNATURES
                        result.technologies[lh.hostname] = []
                        for tech_name in lh.technologies:
                            from submap.core.models import Technology
                            result.technologies[lh.hostname].append(
                                Technology(name=tech_name)
                            )

                progress.update(task_live, completed=len(resolved_hosts), description=f"[bold]Live Host Detection ({len(live_hosts)} live)")
                self._status(f"Detected [bold green]{len(live_hosts)}[/] live hosts")

            # ── STAGE 4: Port Scanning ────────────────────────────────────────
            if cfg.ports and result.live_hosts:
                task_ports = progress.add_task("[bold]Port Scanning", total=None)
                scanner = PortScanner(
                    threads=cfg.threads,
                    timeout=cfg.timeout,
                    rate_limit=cfg.rate_limit,
                )
                hosts_to_scan = [h.hostname for h in result.live_hosts]
                ports = await scanner.scan(hosts_to_scan)
                result.ports = ports
                progress.update(task_ports, completed=True, total=1, description=f"[bold]Port Scanning ({len(ports)} open ports)")
                self._status(f"Found [bold cyan]{len(ports)}[/] open ports")

            # ── STAGE 5: JavaScript Analysis ──────────────────────────────────
            js_content: dict[str, str] = {}
            if cfg.js and result.live_hosts:
                task_js = progress.add_task("[bold]JavaScript Analysis", total=None)
                analyzer = JSAnalyzer(
                    timeout=cfg.timeout,
                    threads=cfg.threads,
                    rate_limit=cfg.rate_limit,
                    proxy=cfg.proxy,
                )
                live_urls = [h.hostname for h in result.live_hosts]
                js_findings, js_content = await analyzer.analyze_hosts(live_urls)
                result.js_findings = js_findings
                secret_count = sum(len(j.hardcoded_secrets) for j in js_findings)
                progress.update(task_js, completed=True, total=1, description=f"[bold]JavaScript Analysis ({len(js_findings)} files, {secret_count} secrets)")

            # ── STAGE 6: API Discovery ────────────────────────────────────────
            if cfg.api and result.live_hosts:
                task_api = progress.add_task("[bold]API Discovery", total=None)
                api_disc = APIDiscovery(
                    timeout=cfg.timeout,
                    threads=cfg.threads,
                    rate_limit=cfg.rate_limit,
                    proxy=cfg.proxy,
                    verbose=cfg.verbose,
                )
                live_urls = [h.hostname for h in result.live_hosts]
                api_endpoints = await api_disc.discover(live_urls, js_content)
                result.api_endpoints = api_endpoints
                progress.update(task_api, completed=True, total=1, description=f"[bold]API Discovery ({len(api_endpoints)} endpoints)")
                self._status(f"Discovered [bold cyan]{len(api_endpoints)}[/] API endpoints")

            # ── STAGE 7: URL Reconnaissance ───────────────────────────────────
            if cfg.urls:
                task_urls = progress.add_task("[bold]URL Reconnaissance", total=None)
                url_recon = URLRecon(
                    timeout=cfg.timeout,
                    threads=cfg.threads,
                    rate_limit=cfg.rate_limit,
                    proxy=cfg.proxy,
                )
                urls = await url_recon.collect([domain])
                result.urls = urls
                progress.update(task_urls, completed=True, total=1, description=f"[bold]URL Reconnaissance ({len(urls)} URLs)")

            # ── STAGE 8: Information Leak Detection ───────────────────────────
            if cfg.leaks and result.live_hosts:
                task_leaks = progress.add_task("[bold]Leak Detection", total=None)
                leak_detector = LeakDetector(
                    timeout=cfg.timeout,
                    threads=cfg.threads,
                    rate_limit=cfg.rate_limit,
                    proxy=cfg.proxy,
                    verbose=cfg.verbose,
                )
                live_hosts_urls = [h.hostname for h in result.live_hosts]
                leaks = await leak_detector.detect(live_hosts_urls)
                result.leaks = leaks
                progress.update(task_leaks, completed=True, total=1, description=f"[bold]Leak Detection ({len(leaks)} found)")
                self._status(f"Found [bold red]{len(leaks)}[/] potential exposure(s)")

            # ── STAGE 9: Risk Classification ──────────────────────────────────
            task_risk = progress.add_task("[bold]Risk Classification", total=None)
            classifier = RiskClassifier()
            all_findings = []

            if result.leaks:
                all_findings.extend(classifier.classify_leaks(result.leaks))
            if result.ports:
                all_findings.extend(classifier.classify_ports(result.ports))
            if result.live_hosts:
                all_findings.extend(classifier.classify_tls(result.live_hosts))
                all_findings.extend(classifier.classify_live_hosts(result.live_hosts))
                if cfg.headers:
                    all_findings.extend(classifier.classify_headers(result.live_hosts))
            if result.js_findings:
                all_findings.extend(classifier.classify_js_findings(result.js_findings))

            result.findings = all_findings
            result.update_stats()

            progress.update(task_risk, completed=True, total=1, description=f"[bold]Risk Classification ({len(all_findings)} findings)")

        # ── Display results ───────────────────────────────────────────────────
        result.finished_at = datetime.utcnow()

        if not cfg.silent:
            self._print_summary(result)

        # ── Asset map ─────────────────────────────────────────────────────────
        asset_map = build_asset_map(result)

        if not cfg.silent and cfg.verbose:
            self.console.print(render_terminal_map(result))

        # ── Save results ──────────────────────────────────────────────────────
        if cfg.save and output_dir:
            writer = ReportWriter(output_dir)
            writer.write_all(result, asset_map)
            self.console.print(
                f"\n[bold green]✓[/] Results saved to [bold white]{output_dir}[/]"
            )

        self.db.save_scan_result(result)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _status(self, msg: str) -> None:
        if not self.config.silent:
            self.console.print(f"  [dim]›[/] {msg}")

    def _print_summary(self, result: ScanResult) -> None:
        self.console.print()

        # Severity table
        table = Table(title=f"[bold cyan]Scan Summary — {result.domain}[/]", border_style="cyan")
        table.add_column("Metric", style="bold white")
        table.add_column("Count", justify="right")

        table.add_row("Subdomains", str(result.total_subdomains))
        table.add_row("Resolved", str(result.total_resolved))
        table.add_row("Live Hosts", str(result.total_live))
        table.add_row("API Endpoints", str(result.total_apis))
        table.add_row("URLs", str(result.total_urls))
        table.add_row("─" * 15, "─" * 6)
        table.add_row("[bold red]HIGH[/]", f"[bold red]{result.total_high}[/]")
        table.add_row("[bold yellow]MEDIUM[/]", f"[bold yellow]{result.total_medium}[/]")
        table.add_row("[bold blue]LOW[/]", f"[bold blue]{result.total_low}[/]")

        self.console.print(table)
        self.console.print()

        # Top findings
        high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
        if high_findings:
            self.console.print("[bold red]  🔴 HIGH Findings:[/]")
            for f in high_findings[:5]:
                self.console.print(f"  [red]  [{f.finding_id}][/] {f.asset} — {f.finding_type}")
            if len(high_findings) > 5:
                self.console.print(f"  [dim]  ... and {len(high_findings) - 5} more[/]")
