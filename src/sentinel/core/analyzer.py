from collections.abc import Mapping


class DNSAnalyzer:
    """Analyse les résultats DNS."""

    @staticmethod
    def summarize(results: Mapping[str, list[str]]) -> dict[str, int]:
        return {
            record_type: len(values)
            for record_type, values in results.items()
        }
    
    TECHNOLOGIES = {
        "google": "Google",
        "microsoft": "Microsoft",
        "hubspot": "HubSpot",
        "stripe": "Stripe",
        "zoom": "Zoom",
        "dropbox": "Dropbox",
        "docker": "Docker",
        "notion": "Notion",
        "airtable": "Airtable",
        "atlassian": "Atlassian",
        "twilio": "Twilio",
        "apple": "Apple",
        "miro": "Miro",
    }

    @classmethod
    def detect_services(cls, txt_records: list[str]) -> list[str]:

        found = set()

        for record in txt_records:

            lower = record.lower()

            for keyword, service in cls.TECHNOLOGIES.items():

                if keyword in lower:
                    found.add(service)

        return sorted(found)