from __future__ import annotations

import requests


class ASNScanner:

    def scan(self, target: str):

        ip = requests.get(
            f"https://dns.google/resolve?name={target}&type=A",
            timeout=5,
        ).json()

        if "Answer" not in ip:

            return {}

        address = ip["Answer"][0]["data"]

        data = requests.get(
            f"https://ipapi.co/{address}/json/",
            timeout=5,
        ).json()

        return {

            "ip": address,

            "asn": data.get("asn"),

            "provider": data.get("org"),

            "city": data.get("city"),

            "country": data.get("country_name"),

            "continent": data.get("continent_code"),

            "latitude": data.get("latitude"),

            "longitude": data.get("longitude"),

            "timezone": data.get("timezone"),

        }