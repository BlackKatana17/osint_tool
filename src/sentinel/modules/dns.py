from __future__ import annotations

import dns.resolver

from sentinel.core.analyzer import DNSAnalyzer


class DNSScanner:

    RECORDS = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "SOA",
        "CAA",
    ]

    def __init__(self):

        self.resolver = dns.resolver.Resolver()

        self.resolver.lifetime = 4

        self.resolver.timeout = 4

    def _lookup(self, target: str, record_type: str):

        try:

            answers = self.resolver.resolve(
                target,
                record_type,
            )

            return [str(answer).strip() for answer in answers]

        except Exception:

            return []

    def _spf(self, txt_records):

        for record in txt_records:

            if record.lower().startswith("v=spf1"):

                return record

        return None

    def _dmarc(self, target):

        try:

            answers = self.resolver.resolve(
                f"_dmarc.{target}",
                "TXT",
            )

            for answer in answers:

                value = str(answer).replace('"', "")

                if value.lower().startswith("v=dmarc1"):

                    return value

        except Exception:

            pass

        return None

    def _dkim(self, target):

        selectors = [
            "default",
            "selector1",
            "selector2",
            "google",
            "k1",
            "mail",
            "smtp",
        ]

        found = {}

        for selector in selectors:

            try:

                answers = self.resolver.resolve(
                    f"{selector}._domainkey.{target}",
                    "TXT",
                )

                values = []

                for answer in answers:

                    values.append(
                        str(answer).replace('"', "")
                    )

                if values:

                    found[selector] = values

            except Exception:

                continue

        return found

    def scan(self, target: str):

        results = {}

        for record in self.RECORDS:

            results[record] = self._lookup(
                target,
                record,
            )

        txt = results["TXT"]

        results["SPF"] = self._spf(txt)

        results["DMARC"] = self._dmarc(target)

        results["DKIM"] = self._dkim(target)

        results["Technologies"] = (
            DNSAnalyzer.detect_services(txt)
        )

        results["Summary"] = (
            DNSAnalyzer.summarize(results)
        )

        return results