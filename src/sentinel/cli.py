import typer

from sentinel.core.engine import Engine

app = typer.Typer(
    add_completion=False,
    help="Sentinel OSINT Framework",
)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain"),
):
    """
    Scan a target.
    """
    engine = Engine()
    engine.run(target)


@app.callback(invoke_without_command=True)
def default(
    ctx: typer.Context,
    target: str = typer.Argument(None),
):
    """
    Allows:
        sentinel openai.com
    """

    if ctx.invoked_subcommand is None:

        if target is None:
            raise typer.BadParameter("Please specify a target.")

        Engine().run(target)