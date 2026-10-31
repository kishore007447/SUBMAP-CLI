"""DNS Intelligence Engine."""
from __future__ import annotations

import asyncio
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.rdatatype

from submap.core.models import DNSRecord, DNSRecordType, DNSResult
from submap.utils.logger import get_logger
from submap.utils.validator import is_private_ip

log = get_logger(__name__)

DEFAULT_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
WILDCARD_TEST_PREFIX = "this-subdomain-should-not-exist-submap-check"


class DNSEngine:
    """Async DNS resolution and intelligence collector."""

    def __init__(
        self,
        resolvers: list[str] | None = None,
        timeout: int = 5,
        threads: int = 20,
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.nameservers = resolvers or DEFAULT_RESOLVERS
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout * 2
        self._sem = asyncio.Semaphore(threads)
        self._wildcard_ips: dict[str, set[str]] = {}  # domain → wildcard IPs

    # ── Public API ────────────────────────────────────────────────────────────

    async def check_wildcard(self, domain: str) -> set[str]:
        """Return IPs if domain has wildcard DNS, empty set otherwise."""
        test_host = f"{WILDCARD_TEST_PREFIX}.{domain}"
        try:
            answer = await self._resolver.resolve(test_host, "A")
            ips = {r.address for r in answer}
            self._wildcard_ips[domain] = ips
            return ips
        except Exception:
            return set()

    async def resolve_all(
        self, hostnames: list[str], domain: str
    ) -> dict[str, DNSResult]:
        """Resolve a batch of hostnames."""
        wildcard_ips = await self.check_wildcard(domain)
        tasks = [self._resolve_one(h, wildcard_ips) for h in hostnames]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        out: dict[str, DNSResult] = {}
        for hostname, result in zip(hostnames, results_list):
            if isinstance(result, DNSResult):
                out[hostname] = result
            else:
                out[hostname] = DNSResult(hostname=hostname, resolved=False)
        return out

    async def _resolve_one(
        self, hostname: str, wildcard_ips: set[str]
    ) -> DNSResult:
        async with self._sem:
            result = DNSResult(hostname=hostname)
            try:
                await self._collect_a(result, wildcard_ips)
                await self._collect_aaaa(result)
                await self._collect_cname(result)
                await self._collect_mx(result)
                await self._collect_ns(result)
                await self._collect_txt(result)
                await self._collect_caa(result)
                await self._collect_ptr(result)
                result.resolved = bool(result.ip_addresses)
            except Exception as exc:
                log.debug("DNS resolve error for %s: %s", hostname, exc)
        return result

    # ── Record collectors ─────────────────────────────────────────────────────

    async def _collect_a(self, result: DNSResult, wildcard_ips: set[str]) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "A")
            ips = [r.address for r in answer]
            # Wildcard detection: if all IPs match wildcard IPs, flag it
            if wildcard_ips and all(ip in wildcard_ips for ip in ips):
                result.is_wildcard = True
            for ip in ips:
                if not is_private_ip(ip):
                    result.ip_addresses.append(ip)
                    result.records.append(
                        DNSRecord(
                            hostname=result.hostname,
                            record_type=DNSRecordType.A,
                            value=ip,
                            ttl=answer.rrset.ttl if answer.rrset else 0,
                        )
                    )
        except (dns.exception.DNSException, Exception):
            pass

    async def _collect_aaaa(self, result: DNSResult) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "AAAA")
            for r in answer:
                result.records.append(
                    DNSRecord(
                        hostname=result.hostname,
                        record_type=DNSRecordType.AAAA,
                        value=r.address,
                        ttl=answer.rrset.ttl if answer.rrset else 0,
                    )
                )
        except Exception:
            pass

    async def _collect_cname(self, result: DNSResult) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "CNAME")
            for r in answer:
                target = str(r.target).rstrip(".")
                result.cname_chain.append(target)
                result.records.append(
                    DNSRecord(
                        hostname=result.hostname,
                        record_type=DNSRecordType.CNAME,
                        value=target,
                        ttl=answer.rrset.ttl if answer.rrset else 0,
                    )
                )
        except Exception:
            pass

    async def _collect_mx(self, result: DNSResult) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "MX")
            for r in answer:
                mx = f"{r.preference} {str(r.exchange).rstrip('.')}"
                result.mx_records.append(mx)
                result.records.append(
                    DNSRecord(
                        hostname=result.hostname,
                        record_type=DNSRecordType.MX,
                        value=mx,
                        ttl=answer.rrset.ttl if answer.rrset else 0,
                    )
                )
        except Exception:
            pass

    async def _collect_ns(self, result: DNSResult) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "NS")
            for r in answer:
                ns = str(r.target).rstrip(".")
                result.ns_records.append(ns)
                result.records.append(
                    DNSRecord(
                        hostname=result.hostname,
                        record_type=DNSRecordType.NS,
                        value=ns,
                        ttl=answer.rrset.ttl if answer.rrset else 0,
                    )
                )
        except Exception:
            pass

    async def _collect_txt(self, result: DNSResult) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "TXT")
            for r in answer:
                txt = "".join(s.decode("utf-8", errors="replace") for s in r.strings)
                result.txt_records.append(txt)
                result.records.append(
                    DNSRecord(
                        hostname=result.hostname,
                        record_type=DNSRecordType.TXT,
                        value=txt[:512],
                        ttl=answer.rrset.ttl if answer.rrset else 0,
                    )
                )
        except Exception:
            pass

    async def _collect_caa(self, result: DNSResult) -> None:
        try:
            answer = await self._resolver.resolve(result.hostname, "CAA")
            for r in answer:
                caa = f"{r.flags} {r.tag.decode()} {r.value.decode()}"
                result.caa_records.append(caa)
                result.records.append(
                    DNSRecord(
                        hostname=result.hostname,
                        record_type=DNSRecordType.CAA,
                        value=caa,
                    )
                )
        except Exception:
            pass

    async def _collect_ptr(self, result: DNSResult) -> None:
        for ip in result.ip_addresses[:2]:  # limit reverse lookups
            try:
                rev = dns.reversename.from_address(ip)
                answer = await self._resolver.resolve(rev, "PTR")
                for r in answer:
                    ptr = str(r.target).rstrip(".")
                    result.ptr_records.append(ptr)
                    result.records.append(
                        DNSRecord(
                            hostname=ip,
                            record_type=DNSRecordType.PTR,
                            value=ptr,
                        )
                    )
            except Exception:
                pass
