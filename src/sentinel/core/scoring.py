class SecurityScore:

    def calculate(self, results: dict) -> int:

        score = 100

        http = (
            results["modules"]
            .get("http", {})
            .get("data", {})
        )

        headers = http.get("headers", {})

        required = [
            "HSTS",
            "CSP",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ]

        for header in required:

            if not headers.get(header):

                score -= 5

        tls = (
            results["modules"]
            .get("tls", {})
            .get("data", {})
        )

        if tls.get("expired"):

            score -= 20

        return max(score, 0)