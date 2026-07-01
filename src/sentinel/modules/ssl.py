import socket
import ssl
from datetime import datetime


class SSLScanner:
    """
    SSL/TLS scanner.
    """

    def scan(self, target: str) -> dict:

        try:

            context = ssl.create_default_context()

            with socket.create_connection((target, 443), timeout=5) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=target,
                ) as secure_socket:

                    cert = secure_socket.getpeercert()

                    expires = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z",
                    )

                    days_remaining = (
                        expires - datetime.utcnow()
                    ).days

                    issuer = dict(
                        x[0] for x in cert["issuer"]
                    )

                    subject = dict(
                        x[0] for x in cert["subject"]
                    )

                    san = []

                    for item in cert.get(
                        "subjectAltName",
                        [],
                    ):
                        san.append(item[1])

                    return {
                        "valid": True,
                        "tls_version": secure_socket.version(),
                        "cipher": secure_socket.cipher()[0],
                        "issuer": issuer.get("organizationName", "-"),
                        "issuer_cn": issuer.get("commonName", "-"),
                        "subject": subject.get("commonName", "-"),
                        "expires": expires.strftime("%Y-%m-%d"),
                        "days_remaining": days_remaining,
                        "san": san,
                    }

        except Exception as exc:

            return {
                "valid": False,
                "error": str(exc),
            }