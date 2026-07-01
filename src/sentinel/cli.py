import typer
from rich import print_json
from sentinel.core.engine import Engine
from sentinel.core.reporter import Reporter

from sentinel.core.engine import Engine

app = typer.Typer(
    add_completion=False,
    help="Sentinel OSINT Framework",
)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain"),
):
    engine = Engine()
    result = engine.run(target)

    print_json(data=result)


@app.callback(invoke_without_command=True)
def default(ctx: typer.Context, target: str = typer.Argument(None)):

    if ctx.invoked_subcommand is None:

        if target is None:
            raise typer.BadParameter("Please specify a target.")

        result = Engine().run(target)

        Reporter(result).render()