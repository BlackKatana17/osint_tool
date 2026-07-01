import requests

def run(url):
    paths = [
        "/.well-known/security.txt",
        "/security.txt"
    ]

    for p in paths:
        try:
            r = requests.get(url.rstrip("/") + p, timeout=5)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass

    return ""