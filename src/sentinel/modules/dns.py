import dns.resolver


class DNSScanner:
    """Récupère les principaux enregistrements DNS d'un domaine."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]

    def scan(self, domain: str) -> dict[str, list[str]]:
        results: dict[str, list[str]] = {}

        for record_type in self.RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(answer) for answer in answers]
            except Exception:
                results[record_type] = []

        return results