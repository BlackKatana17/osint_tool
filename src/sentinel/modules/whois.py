from __future__ import annotations

from datetime import datetime

import whois


class WhoisScanner:

    @staticmethod
    def _normalize_date(value):

        if value is None:
            return None

        if isinstance(value, list):
            value = value[0]

        if isinstance(value, datetime):
            return value.isoformat()

        return str(value)

    @staticmethod
    def _normalize(value):

        if isinstance(value, list):

            return sorted(
                {
                    str(v).strip()
                    for v in value
                    if v
                }
            )

        return value

    def scan(self, target: str):

        record = whois.whois(target)

        return {

            "domain": record.domain_name,

            "registrar": record.registrar,

            "whois_server": record.whois_server,

            "creation_date":
                self._normalize_date(
                    record.creation_date
                ),

            "updated_date":
                self._normalize_date(
                    record.updated_date
                ),

            "expiration_date":
                self._normalize_date(
                    record.expiration_date
                ),

            "name_servers":
                self._normalize(
                    record.name_servers
                ),

            "status":
                self._normalize(
                    record.status
                ),

            "dnssec":
                record.dnssec,

            "emails":
                self._normalize(
                    record.emails
                ),

            "registrant_country":
                getattr(
                    record,
                    "country",
                    None,
                ),

            "registrant_org":
                getattr(
                    record,
                    "org",
                    None,
                ),
        }
    
