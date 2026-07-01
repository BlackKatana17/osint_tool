import typer

from sentinel.core.banner import print_banner
from sentinel.core.engine import Engine

app = typer.Typer()


@app.command()
def scan(target: str):

    print_banner()

    engine = Engine()

    engine.run(target)