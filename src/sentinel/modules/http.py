from __future__ import annotations

import time

import requests

from sentinel.core.analyzer import HTTPAnalyzer


class HTTPScanner:

    def __init__(self):

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": (
                    "Sentinel-OSINT/1.0 "
                    "(Passive Security Scanner)"
                )
            }
        )

    def _request(self, url: str):

        started = time.perf_counter()

        response = self.session.get(
            url,
            timeout=8,
            allow_redirects=True,
        )

        elapsed = round(
            (time.perf_counter() - started) * 1000
        )

        return response, elapsed

    def scan(self, target: str):

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        last_error = None

        for url in urls:

            try:

                response, elapsed = self._request(url)

                headers = dict(response.headers)

                return {
                    "url": response.url,
                    "status": response.status_code,
                    "reason": response.reason,
                    "elapsed_ms": elapsed,
                    "response_grade":
                        HTTPAnalyzer.response_grade(elapsed),
                    "https":
                        response.url.startswith("https://"),
                    "server":
                        HTTPAnalyzer.detect_server(headers),
                    "headers":
                        HTTPAnalyzer.analyze(headers),
                    "content_length":
                        headers.get("Content-Length"),
                    "encoding":
                        response.encoding,
                    "cookies":
                        list(response.cookies.keys()),
                    "redirects":
                        [
                            r.url
                            for r in response.history
                        ],
                }

            except Exception as exc:

                last_error = exc

        raise RuntimeError(last_error)