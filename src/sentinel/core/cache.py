from pathlib import Path
import json

CACHE_DIR = Path.home() / ".sentinel"
CACHE_DIR.mkdir(exist_ok=True)

def save(name: str, data: dict):
    with open(CACHE_DIR / f"{name}.json", "w", encoding="utf8") as f:
        json.dump(data, f, indent=4)

def load(name: str):
    path = CACHE_DIR / f"{name}.json"
    if not path.exists():
        return None

    with open(path, encoding="utf8") as f:
        return json.load(f)