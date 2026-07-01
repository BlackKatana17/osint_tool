def export(report, filename):
    html = "<html><body><pre>"
    html += str(report)
    html += "</pre></body></html>"

    with open(filename, "w", encoding="utf8") as f:
        f.write(html)