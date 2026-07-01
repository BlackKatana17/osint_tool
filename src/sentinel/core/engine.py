from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console

from sentinel.modules.asn import ASNScanner
from sentinel.modules.dns import DNSScanner
from sentinel.modules.http import HTTPScanner
from sentinel.modules.ip import IPScanner
from sentinel.modules.tls import TLSScanner
from sentinel.modules.whois import WhoisScanner

from sentinel.modules.crtsh import run as crtsh_scan
from sentinel.modules.robots import run as robots_scan
from sentinel.modules.securitytxt import run as securitytxt_scan
from sentinel.modules.sitemap import run as sitemap_scan

console = Console()


class Engine:

    def __init__(self):

        self.modules = {
            "dns": DNSScanner(),
            "http": HTTPScanner(),
            "tls": TLSScanner(),
            "whois": WhoisScanner(),
            "ip": IPScanner(),
            "asn": ASNScanner(),

            "crtsh": crtsh_scan,
            "robots": robots_scan,
            "securitytxt": securitytxt_scan,
            "sitemap": sitemap_scan,
        }

    def _execute_module(self, name: str, scanner, target: str):

        started = time.perf_counter()

        try:

            result = scanner.scan(target)

            elapsed = round((time.perf_counter() - started) * 1000)

            return (
                name,
                {
                    "success": True,
                    "time_ms": elapsed,
                    "data": result,
                },
            )

        except Exception as exc:

            elapsed = round((time.perf_counter() - started) * 1000)

            return (
                name,
                {
                    "success": False,
                    "time_ms": elapsed,
                    "error": str(exc),
                    "data": {},
                },
            )

    def run(self, target: str) -> dict:

        started = time.perf_counter()

        console.rule(f"[cyan]Scanning {target}")

        results = {
            "target": target,
            "started": time.time(),
            "modules": {},
        }

        with ThreadPoolExecutor(max_workers=8) as executor:

            futures = [
                executor.submit(
                    self._execute_module,
                    name,
                    scanner,
                    target,
                )
                for name, scanner in self.modules.items()
            ]

            for future in as_completed(futures):

                name, module_result = future.result()

                results["modules"][name] = module_result

        results["duration_ms"] = round(
            (time.perf_counter() - started) * 1000
        )

        return results