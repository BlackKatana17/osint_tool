class DNSAnalyzer:

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
        "canva": "Canva",
        "figma": "Figma",
        "box": "Box",
        "oracle": "Oracle Cloud",
        "tailscale": "Tailscale",
        "hibp": "HaveIBeenPwned",
        "smartsheet": "Smartsheet",
        "onetrust": "OneTrust",
        "calendly": "Calendly",
        "autodesk": "Autodesk",
        "wrike": "Wrike",
        "airalo": "Airalo",
        "parsec": "Parsec",
    }

    @staticmethod
    def summarize(records: dict) -> dict:

        summary = {}

        for record_type, values in records.items():
            summary[record_type] = len(values)

        return summary

    @classmethod
    def detect_services(cls, txt_records: list[str]) -> list[str]:

        found = set()

        for record in txt_records:

            record = record.lower()

            for keyword, service in cls.TECHNOLOGIES.items():

                if keyword in record:
                    found.add(service)

        return sorted(found)


class HTTPAnalyzer:

    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "cross-origin-opener-policy": "COOP",
        "cross-origin-resource-policy": "CORP",
        "cross-origin-embedder-policy": "COEP",
    }

    SERVER_KEYWORDS = {
        "cloudflare": "Cloudflare",
        "nginx": "Nginx",
        "apache": "Apache",
        "iis": "Microsoft IIS",
        "caddy": "Caddy",
        "envoy": "Envoy",
    }

    @classmethod
    def analyze(cls, headers: dict) -> dict:

        headers = {k.lower(): v for k, v in headers.items()}

        result = {}

        result["Server"] = headers.get("server", "Unknown")
        result["Content-Type"] = headers.get("content-type", "-")
        result["Cache-Control"] = headers.get("cache-control", "-")

        for header, display in cls.SECURITY_HEADERS.items():
            result[display] = header in headers

        return result

    @classmethod
    def detect_server(cls, headers: dict) -> str:

        server = headers.get("server", "").lower()

        for keyword, name in cls.SERVER_KEYWORDS.items():

            if keyword in server:
                return name

        return server if server else "Unknown"

    @staticmethod
    def response_grade(elapsed: int) -> str:

        if elapsed < 200:
            return "Excellent"

        if elapsed < 500:
            return "Good"

        if elapsed < 1000:
            return "Average"

        return "Slow"