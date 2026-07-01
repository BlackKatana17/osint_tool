import json

def export(report, filename):
    with open(filename, "w", encoding="utf8") as f:
        json.dump(report, f, indent=4)