from rich.console import Console
from rich.table import Table

from sentinel.modules.dns import DNSScanner
from sentinel.core.analyzer import DNSAnalyzer

console = Console()


class Engine:

    def run(self, target: str):
        
        
        scanner = DNSScanner()

        results = scanner.scan(target)
        summary = DNSAnalyzer.summarize(results)

        console.rule("[bold cyan]DNS Summary")

        for record, count in summary.items():
            console.print(f"{record:<5} : {count}")

        table = Table(title=f"DNS Records - {target}")

        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Valeur", style="green")

        for record_type, values in results.items():

            if values:
                for value in values:
                    table.add_row(record_type, value)
            else:
                table.add_row(record_type, "-")

        console.print(table)

        services = DNSAnalyzer.detect_services(results["TXT"])

        console.rule("[bold green]Detected Services")

        for service in services:
            console.print(f"✓ {service}")