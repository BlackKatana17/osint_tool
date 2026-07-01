from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class TLSScanner:

    PORT = 443

    def scan(self, target: str):

        context = ssl.create_default_context()

        with socket.create_connection(
            (target, self.PORT),
            timeout=8,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=target,
            ) as tls:

                der = tls.getpeercert(binary_form=True)

                cert = x509.load_der_x509_certificate(der)

                protocol = tls.version()

                cipher = tls.cipher()

        subject = {
            attr.oid._name: attr.value
            for attr in cert.subject
        }

        issuer = {
            attr.oid._name: attr.value
            for attr in cert.issuer
        }

        san = []

        try:

            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)

        except Exception:

            pass

        expires = cert.not_valid_after_utc

        issued = cert.not_valid_before_utc

        remaining = (expires - datetime.utcnow().astimezone()).days

        public_key = cert.public_key()

        try:

            key_size = public_key.key_size

        except Exception:

            key_size = None

        pem = cert.public_bytes(
            serialization.Encoding.PEM
        )

        sha1 = hashlib.sha1(der).hexdigest()

        sha256 = hashlib.sha256(der).hexdigest()

        return {

            "protocol": protocol,

            "cipher": cipher[0],

            "cipher_bits": cipher[2],

            "issued": issued.isoformat(),

            "expires": expires.isoformat(),

            "remaining_days": remaining,

            "expired": remaining < 0,

            "subject": subject,

            "issuer": issuer,

            "common_name": subject.get("commonName"),

            "organization": subject.get("organizationName"),

            "issuer_cn": issuer.get("commonName"),

            "issuer_org": issuer.get("organizationName"),

            "serial_number": str(cert.serial_number),

            "signature_algorithm": cert.signature_hash_algorithm.name,

            "public_key_bits": key_size,

            "sha1": sha1,

            "sha256": sha256,

            "san": san,

            "certificate": pem.decode(),

        }