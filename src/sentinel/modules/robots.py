import requests

class RobotsScanner:

    def run(self, url):
        try:
            r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)

            return {
                "status": r.status_code,
                "content": r.text
            }

        except Exception as e:
            return {
                "error": str(e)
            }