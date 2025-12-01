import typer
from .commands.scan import scan_package
from .commands.file import scan_file
from .commands.batch import scan_batch

from safepackages import __version__

app = typer.Typer(help="SafePackages CLI")

app.command(name="scan")(scan_package)
app.command(name="file")(scan_file)
app.command(name="batch")(scan_batch)


def version_callback(value: bool):
    if value:
        typer.echo(f"SafePackages CLI v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    pass


if __name__ == "__main__":
    app()
