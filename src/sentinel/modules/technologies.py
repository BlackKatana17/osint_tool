import requests

def run(url):
    try:
        r = requests.get(url, timeout=5)

        return {
            "server": r.headers.get("Server"),
            "powered_by": r.headers.get("X-Powered-By"),
        }

    except Exception:
        return {}