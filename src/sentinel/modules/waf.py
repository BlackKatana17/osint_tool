import requests

WAF_HEADERS = [
    "cf-ray",
    "x-sucuri-id",
    "x-cdn",
    "x-fireeye"
]

def run(url):
    try:
        headers = requests.get(url, timeout=5).headers

        return [
            h
            for h in WAF_HEADERS
            if h in headers
        ]

    except Exception:
        return []