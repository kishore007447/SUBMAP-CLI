"""Port and Service Discovery (Naabu + Nmap integration)."""
from __future__ import annotations

import asyncio
import json
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from submap.core.models import PortInfo
from submap.utils.logger import get_logger

log = get_logger(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 1723, 2049, 2083,
    2096, 2082, 2222, 3000, 3306, 3389, 4443, 4848, 5000, 5432,
    5900, 6379, 6443, 7001, 8000, 8001, 8008, 8080, 8081, 8443,
    8888, 9000, 9090, 9200, 9300, 10000, 27017, 27018, 28017,
]


class PortScanner:
    """Port scanner using Naabu and Nmap."""

    def __init__(
        self,
        *,
        ports: list[int] | None = None,
        threads: int = 10,
        timeout: int = 10,
        rate_limit: int = 30,
    ) -> None:
        self.ports = ports or COMMON_PORTS
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit

    async def scan(self, hosts: list[str]) -> list[PortInfo]:
        """Run port scanning against a list of hosts."""
        results: list[PortInfo] = []

        naabu_available = await self._tool_available("naabu")
        nmap_available = await self._tool_available("nmap")

        if naabu_available:
            log.info("Using Naabu for port scanning")
            naabu_results = await self._run_naabu(hosts)
            results.extend(naabu_results)
        elif nmap_available:
            log.info("Using Nmap for port scanning")
            nmap_results = await self._run_nmap(hosts)
            results.extend(nmap_results)
        else:
            log.warning("Neither Naabu nor Nmap found — falling back to basic TCP connect")
            results = await self._tcp_connect_scan(hosts)

        return results

    # ── Naabu ─────────────────────────────────────────────────────────────────

    async def _run_naabu(self, hosts: list[str]) -> list[PortInfo]:
        results: list[PortInfo] = []
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as hf:
            hf.write("\n".join(hosts))
            hosts_file = hf.name

        port_str = ",".join(str(p) for p in self.ports)
        args = [
            "naabu",
            "-list", hosts_file,
            "-p", port_str,
            "-rate", str(self.rate_limit),
            "-timeout", str(self.timeout * 1000),
            "-silent",
            "-json",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            for line in stdout.decode(errors="ignore").splitlines():
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    ip = data.get("ip", host)
                    port = data.get("port", 0)
                    if host and port:
                        results.append(
                            PortInfo(
                                hostname=host,
                                ip_address=ip,
                                port=int(port),
                                protocol="tcp",
                                state="open",
                            )
                        )
                except (json.JSONDecodeError, ValueError):
                    # Fallback: parse "host:port" format
                    if ":" in line.strip():
                        parts = line.strip().rsplit(":", 1)
                        if len(parts) == 2:
                            try:
                                results.append(
                                    PortInfo(
                                        hostname=parts[0],
                                        ip_address=parts[0],
                                        port=int(parts[1]),
                                        protocol="tcp",
                                        state="open",
                                    )
                                )
                            except ValueError:
                                pass
        except FileNotFoundError:
            log.debug("Naabu not found")
        except Exception as exc:
            log.debug("Naabu error: %s", exc)

        try:
            Path(hosts_file).unlink(missing_ok=True)
        except Exception:
            pass

        return results

    # ── Nmap ──────────────────────────────────────────────────────────────────

    async def _run_nmap(self, hosts: list[str]) -> list[PortInfo]:
        results: list[PortInfo] = []
        port_str = ",".join(str(p) for p in self.ports)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as outf:
            out_file = outf.name

        args = [
            "nmap",
            "-p", port_str,
            "--open",
            "-sV",
            "--version-intensity", "3",
            "-T3",
            "-oX", out_file,
            "--host-timeout", "60s",
        ] + hosts

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=600)
            results = self._parse_nmap_xml(out_file)
        except FileNotFoundError:
            log.debug("Nmap not found")
        except Exception as exc:
            log.debug("Nmap error: %s", exc)

        try:
            Path(out_file).unlink(missing_ok=True)
        except Exception:
            pass

        return results

    @staticmethod
    def _parse_nmap_xml(xml_file: str) -> list[PortInfo]:
        results: list[PortInfo] = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall("host"):
                hostname = ""
                ip_address = ""
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip_address = addr.get("addr", "")
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hn in hostnames_elem.findall("hostname"):
                        hostname = hn.get("name", "") or ""
                        break
                hostname = hostname or ip_address
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")
                    service_elem = port_elem.find("service")
                    service = ""
                    version = ""
                    if service_elem is not None:
                        service = service_elem.get("name", "")
                        version = service_elem.get("version", "")
                        product = service_elem.get("product", "")
                        if product:
                            version = f"{product} {version}".strip()
                    results.append(
                        PortInfo(
                            hostname=hostname,
                            ip_address=ip_address,
                            port=port_id,
                            protocol=protocol,
                            state="open",
                            service=service,
                            version=version,
                        )
                    )
        except Exception as exc:
            log.debug("Nmap XML parse error: %s", exc)
        return results

    # ── Fallback: basic TCP connect ───────────────────────────────────────────

    async def _tcp_connect_scan(self, hosts: list[str]) -> list[PortInfo]:
        results: list[PortInfo] = []
        sem = asyncio.Semaphore(self.threads * 10)

        async def check(host: str, port: int) -> None:
            async with sem:
                try:
                    conn = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=3)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    results.append(
                        PortInfo(
                            hostname=host,
                            ip_address=host,
                            port=port,
                            protocol="tcp",
                            state="open",
                        )
                    )
                except Exception:
                    pass

        tasks = [check(h, p) for h in hosts for p in self.ports]
        await asyncio.gather(*tasks)
        return results

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    async def _tool_available(tool: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                tool, "--version",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=5)
            return proc.returncode is not None
        except Exception:
            return False
