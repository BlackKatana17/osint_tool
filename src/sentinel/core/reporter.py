from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class Reporter:

    def __init__(self, result: dict):
        self.result = result
        self.modules = result.get("modules", {})

    def render(self):

        console.rule(f"[bold cyan]Scan Report : {self.result.get('target')}")

        self._render_dns()
        self._render_http()
        self._render_tls()
        self._render_services()

    # ---------------- DNS ----------------
    def _render_dns(self):

        dns = self.modules.get("dns", {}).get("data", {})

        if not dns:
            return

        table = Table(title="DNS Records")

        table.add_column("Type", style="cyan")
        table.add_column("Value")

        for record_type, values in dns.items():

            if isinstance(values, list):

                for v in values:
                    table.add_row(record_type, str(v))

            else:
                table.add_row(record_type, str(values))

        console.print(Panel(table, title="DNS Summary"))

    # ---------------- HTTP ----------------
    def _render_http(self):

        http = self.modules.get("http", {}).get("data", {})

        if not http:
            return

        panel = Panel.fit(
            f"""
[cyan]Status[/cyan]      : {http.get("status")}
[cyan]URL[/cyan]         : {http.get("url")}
[cyan]Response[/cyan]    : {http.get("elapsed_ms")} ms
[cyan]Server[/cyan]      : {http.get("server")}
            """,
            title="HTTP",
        )

        console.print(panel)

        headers = http.get("headers", {})

        table = Table(title="Security Headers")
        table.add_column("Header")
        table.add_column("Status")

        for k, v in headers.items():

            if isinstance(v, bool):
                table.add_row(k, "✓" if v else "✗")
            else:
                table.add_row(k, str(v))

        console.print(table)

    # ---------------- TLS ----------------
    def _render_tls(self):

        tls = self.modules.get("tls", {}).get("data", {})

        if not tls:
            return

        panel = Panel.fit(
            f"""
[cyan]Protocol[/cyan] : {tls.get("protocol")}
[cyan]Cipher[/cyan]   : {tls.get("cipher")}
[cyan]Expires[/cyan]  : {tls.get("expires")}
[cyan]Issuer[/cyan]   : {tls.get("issuer", {}).get("commonName")}
            """,
            title="TLS",
        )

        console.print(panel)

    # ---------------- SERVICES ----------------
    def _render_services(self):

        http = self.modules.get("http", {}).get("data", {})
        headers = http.get("headers", {}) if http else {}

        services = []

        fingerprints = {
            "cloudflare": "Cloudflare",
            "google": "Google",
            "amazon": "AWS",
            "stripe": "Stripe",
            "hubspot": "HubSpot",
        }

        for k, v in headers.items():

            for key, service in fingerprints.items():

                if isinstance(v, str) and key in v.lower():
                    services.append(service)

        if not services:
            return

        console.print(
            Panel(
                "\n".join(f"✓ {s}" for s in sorted(set(services))),
                title="Detected Services",
            )
        )