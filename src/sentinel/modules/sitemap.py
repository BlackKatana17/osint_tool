import requests

def run(url):
    try:
        return requests.get(url.rstrip("/") + "/sitemap.xml", timeout=5).text
    except Exception:
        return ""