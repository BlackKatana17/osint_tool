import socket

COMMON = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    3306,
    3389,
    8080
]

def run(host):
    opened = []

    for port in COMMON:
        sock = socket.socket()
        sock.settimeout(0.5)

        try:
            sock.connect((host, port))
            opened.append(port)
        except Exception:
            pass

        sock.close()

    return opened