import requests

def run(url):
    try:
        return dict(requests.get(url, timeout=5).headers)
    except Exception:
        return {}