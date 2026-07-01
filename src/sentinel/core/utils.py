from urllib.parse import urlparse

def normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target

def hostname(target: str):
    return urlparse(target).hostname