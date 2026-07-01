from reportlab.pdfgen import canvas

def export(report, filename):
    c = canvas.Canvas(filename)

    y = 800

    for line in str(report).splitlines():
        c.drawString(30, y, line)
        y -= 15

    c.save()