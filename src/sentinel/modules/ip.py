from __future__ import annotations

import socket


class IPScanner:

    def scan(self, target: str):

        ipv4 = []

        ipv6 = []

        try:

            for result in socket.getaddrinfo(
                target,
                None,
            ):

                family = result[0]

                address = result[4][0]

                if family == socket.AF_INET:

                    if address not in ipv4:
                        ipv4.append(address)

                elif family == socket.AF_INET6:

                    if address not in ipv6:
                        ipv6.append(address)

        except Exception:

            pass

        return {

            "ipv4": sorted(ipv4),

            "ipv6": sorted(ipv6),

        }
    
