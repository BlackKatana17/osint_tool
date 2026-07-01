from __future__ import annotations

from collections import Counter
from typing import Any

import requests


class CRTSHScanner:

    URL = "https://crt.sh/"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Sentinel OSINT/1.0"
            }
        )

    def _query(self, domain: str) -> list[dict[str, Any]]:
        try:
            response = self.session.get(
                self.URL,
                params={
                    "q": f"%.{domain}",
                    "output": "json",
                },
                timeout=15,
            )

            response.raise_for_status()

            data = response.json()

            return data if isinstance(data, list) else []

        except (requests.RequestException, ValueError):
            return []

    @staticmethod
    def _normalize(records: list[dict[str, Any]]):

        subdomains = set()
        issuers = []
        serials = set()

        for record in records:

            if not isinstance(record, dict):
                continue

            serial = record.get("serial_number")
            if serial:
                serials.add(serial)

            issuer = record.get("issuer_name")
            if issuer:
                issuers.append(issuer)

            value = record.get("name_value", "")
            if not value:
                continue

            for host in value.splitlines():

                host = host.lower().strip()

                if not host:
                    continue

                if host.startswith("*."):
                    host = host[2:]

                subdomains.add(host)

        return (
            sorted(subdomains),
            Counter(issuers).most_common(),
            len(serials),
        )

    def scan(self, target: str):

        records = self._query(target)

        subdomains, issuers, certs = self._normalize(records)

        wildcard = [
            host for host in subdomains if host.startswith("*")
        ]

        return {
            "target": target,
            "certificates": certs,
            "subdomains": subdomains,
            "count": len(subdomains),
            "wildcards": wildcard,
            "issuers": [
                {
                    "name": issuer,
                    "count": count,
                }
                for issuer, count in issuers
            ],
        }