"""
SUBMAP CLI Entry Point
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from submap import __version__, __author__, __author_handle__
from submap.core.banner import print_banner
from submap.core.config import ScanConfig
from submap.core.engine import ScanEngine
from submap.utils.validator import validate_domain, validate_domain_list

app = typer.Typer(
    name="submap",
    help="Advanced Subdomain Discovery, Reconnaissance & Attack Surface Mapping Framework",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(
            f"[bold cyan]SUBMAP[/] v{__version__} — by {__author__} ({__author_handle__})"
        )
        raise typer.Exit()


@app.command()
def scan(
    # ── Input / Output ─────────────────────────────────────────────────────────
    domain: Optional[str] = typer.Option(
        None, "-d", "--domain", help="Single target domain", metavar="DOMAIN"
    ),
    domain_list: Optional[Path] = typer.Option(
        None, "-l", "--list", help="File containing multiple domains", metavar="FILE"
    ),
    output: Optional[Path] = typer.Option(
        None, "-o", "--output", help="Output directory", metavar="DIR"
    ),
    save: bool = typer.Option(False, "-s", "--save", help="Save scan output to disk"),
    resume: bool = typer.Option(False, "--resume", help="Resume interrupted scan"),
    exclude: Optional[str] = typer.Option(
        None, "--exclude", help="Comma-separated domains/hosts to exclude"
    ),
    include: Optional[str] = typer.Option(
        None, "--include", help="Comma-separated host patterns to include"
    ),
    # ── Discovery ──────────────────────────────────────────────────────────────
    passive: bool = typer.Option(True, "--passive/--no-passive", help="Passive enumeration (default: on)"),
    active: bool = typer.Option(False, "--active", help="Active DNS enumeration"),
    bruteforce: bool = typer.Option(False, "--bruteforce", help="DNS brute-force"),
    recursive: bool = typer.Option(False, "--recursive", help="Recursive enumeration"),
    wordlist: Optional[Path] = typer.Option(
        None, "--wordlist", help="Custom wordlist for brute-force", metavar="FILE"
    ),
    resolvers: Optional[Path] = typer.Option(
        None, "--resolvers", help="Custom DNS resolver list", metavar="FILE"
    ),
    # ── Reconnaissance ─────────────────────────────────────────────────────────
    live: bool = typer.Option(True, "--live/--no-live", help="Live host probing (default: on)"),
    dns: bool = typer.Option(True, "--dns/--no-dns", help="DNS record enumeration (default: on)"),
    ports: bool = typer.Option(False, "--ports", help="Port discovery (active — opt-in required)"),
    tech: bool = typer.Option(True, "--tech/--no-tech", help="Technology detection (default: on)"),
    api: bool = typer.Option(False, "--api", help="API discovery"),
    urls: bool = typer.Option(False, "--urls", help="URL collection"),
    js: bool = typer.Option(False, "--js", help="JavaScript analysis"),
    leaks: bool = typer.Option(False, "--leaks", help="Information exposure checks"),
    tls: bool = typer.Option(True, "--tls/--no-tls", help="TLS analysis (default: on)"),
    headers: bool = typer.Option(True, "--headers/--no-headers", help="Security header analysis (default: on)"),
    cloud: bool = typer.Option(False, "--cloud", help="Cloud asset identification"),
    # ── Performance ────────────────────────────────────────────────────────────
    threads: int = typer.Option(
        10, "-t", "--threads", help="Concurrent workers", min=1, max=100
    ),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout (seconds)", min=1),
    retries: int = typer.Option(2, "--retries", help="Retry count", min=0),
    rate_limit: int = typer.Option(
        30, "--rate-limit", help="Requests per second", min=1, max=500
    ),
    delay: float = typer.Option(0.0, "--delay", help="Delay between requests (seconds)"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP proxy URL"),
    # ── General ────────────────────────────────────────────────────────────────
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
    silent: bool = typer.Option(False, "--silent", help="Minimal output"),
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version"
    ),
) -> None:
    """
    [bold cyan]SUBMAP[/] — Advanced Subdomain Discovery & Reconnaissance Framework

    [bold]Examples:[/]
      submap -d example.com
      submap -l domains.txt -o results/
      submap -d example.com --api --urls --js --leaks
      submap -d example.com --passive --active --live --dns --ports --tech -t 20 -o results/
    """
    # ── Validate input ─────────────────────────────────────────────────────────
    if not domain and not domain_list:
        console.print("[bold red]Error:[/] Provide a target with -d/--domain or -l/--list")
        raise typer.Exit(1)

    if domain and domain_list:
        console.print("[bold red]Error:[/] Use -d or -l, not both")
        raise typer.Exit(1)

    if not silent:
        print_banner()

    # ── Build domain list ──────────────────────────────────────────────────────
    targets: list[str] = []

    if domain:
        validated = validate_domain(domain)
        if not validated:
            console.print(f"[bold red]Error:[/] Invalid domain: {domain}")
            raise typer.Exit(1)
        targets = [validated]

    elif domain_list:
        if not domain_list.exists():
            console.print(f"[bold red]Error:[/] Domain list file not found: {domain_list}")
            raise typer.Exit(1)
        targets = validate_domain_list(domain_list)
        if not targets:
            console.print("[bold red]Error:[/] No valid domains found in list")
            raise typer.Exit(1)

    # ── Warn about active features ─────────────────────────────────────────────
    if ports and not silent:
        console.print(
            "[bold yellow]Warning:[/] Port scanning is active — ensure you have authorization"
        )

    # ── Set output dir ─────────────────────────────────────────────────────────
    if output is None and save:
        output = Path("results")

    if output:
        save = True

    # ── Build config ───────────────────────────────────────────────────────────
    config = ScanConfig(
        targets=targets,
        output_dir=output,
        save=save,
        resume=resume,
        exclude=exclude.split(",") if exclude else [],
        include=include.split(",") if include else [],
        passive=passive,
        active=active,
        bruteforce=bruteforce,
        recursive=recursive,
        wordlist=wordlist,
        resolvers=resolvers,
        live=live,
        dns=dns,
        ports=ports,
        tech=tech,
        api=api,
        urls=urls,
        js=js,
        leaks=leaks,
        tls=tls,
        headers=headers,
        cloud=cloud,
        threads=threads,
        timeout=timeout,
        retries=retries,
        rate_limit=rate_limit,
        delay=delay,
        proxy=proxy,
        verbose=verbose,
        silent=silent,
    )

    # ── Run scan ───────────────────────────────────────────────────────────────
    try:
        engine = ScanEngine(config, console)
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user[/]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"[bold red]Fatal error:[/] {exc}")
        if verbose:
            import traceback
            console.print_exception()
        sys.exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
