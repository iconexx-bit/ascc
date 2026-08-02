from pathlib import Path

import typer
from rich import print

app = typer.Typer(name="ascc", help="AI Security Command Center")


@app.callback()
def main() -> None:
    """AI Security Command Center — correlation layer over Trivy, Prowler, Checkov."""


@app.command()
def correlate(
    input: Path = typer.Option(
        ...,
        "--input",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Path to a directory of scanner fixtures (Trivy/Prowler/Checkov JSON).",
    ),
) -> None:
    files = sorted(input.iterdir())
    if not files:
        print(f"[yellow]No files found in[/yellow] {input}")
        raise typer.Exit(code=1)

    print(f"[bold]Reading fixtures from[/bold] {input}")
    for f in files:
        print(f"  - {f.name}")

    print("[cyan]TODO: correlation logic[/cyan]")


if __name__ == "__main__":
    app()
