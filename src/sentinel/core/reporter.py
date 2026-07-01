from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


class Reporter:

    def __init__(self, results: dict):

        self.results = results

    def display(self) -> None:

        self._header()

        self._summary()

        self._modules()

    def _header(self):

        target = self.results["target"]

        duration = self.results["duration_ms"]

        console.print()

        console.print(
            Panel.fit(
                f"[bold cyan]{target}[/]\n\n"
                f"Scan completed in [green]{duration} ms[/]",
                title="Sentinel",
                border_style="cyan",
            )
        )

    def _summary(self):

        table = Table(title="Summary")

        table.add_column("Module", style="cyan")
        table.add_column("Status")
        table.add_column("Time")
        table.add_column("Items")

        for module, result in sorted(
            self.results["modules"].items()
        ):

            status = (
                "[green]OK[/]"
                if result["success"]
                else "[red]FAILED[/]"
            )

            data = result["data"]

            if isinstance(data, dict):

                count = len(data)

            elif isinstance(data, list):

                count = len(data)

            else:

                count = 1 if data else 0

            table.add_row(
                module.upper(),
                status,
                f'{result["time_ms"]} ms',
                str(count),
            )

        console.print()

        console.print(table)

    def _modules(self):

        for module, result in sorted(
            self.results["modules"].items()
        ):

            console.print()

            console.rule(f"[cyan]{module.upper()}")

            if not result["success"]:

                console.print(
                    f"[red]{result['error']}[/]"
                )

                continue

            data = result["data"]

            if isinstance(data, dict):

                table = Table(show_header=False)

                table.add_column(style="cyan")

                table.add_column()

                for key, value in data.items():

                    if isinstance(value, list):

                        value = ", ".join(
                            str(v) for v in value
                        )

                    table.add_row(
                        str(key),
                        str(value),
                    )

                console.print(table)

            elif isinstance(data, list):

                for value in data:

                    console.print(
                        f"• {value}"
                    )

            else:

                console.print(data)