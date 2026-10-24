"""Tridetect CLI."""

import subprocess
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
@click.version_option(package_name="tridetect")
def cli():
    """Tridetect — Tri-vector Phishing Detection System."""


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, show_default=True)
@click.option("--reload", is_flag=True, default=False)
def serve(host: str, port: int, reload: bool):
    """Start the API gateway."""
    console.print(
        Panel.fit(
            f"[bold green]Tridetect API[/bold green]\n"
            f"Host: {host}  Port: {port}\n"
            f"Docs: http://{host}:{port}/docs",
            title="Starting server",
        )
    )
    import uvicorn

    uvicorn.run(
        "tridetect.gateway.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.command("classify-web")
@click.argument("url")
@click.option("--no-ssl", is_flag=True, default=False, help="Skip SSL check")
@click.option("--no-brand", is_flag=True, default=False, help="Skip brand check")
def classify_web(url: str, no_ssl: bool, no_brand: bool):
    """Classify a URL for phishing."""
    from tridetect.modules.web_phishing.classifier import WebPhishingClassifier

    console.print(f"[cyan]Analysing URL:[/cyan] {url}")
    clf = WebPhishingClassifier()
    result = clf.classify(url, check_ssl=not no_ssl, check_brand=not no_brand)
    _print_result(result, module="web")


@cli.command("classify-sms")
@click.argument("text")
@click.option("--sender", default=None, help="Sender phone number")
def classify_sms(text: str, sender: str):
    """Classify an SMS/WhatsApp message for smishing."""
    from tridetect.modules.smishing.classifier import SmishingClassifier

    console.print(f"[cyan]Analysing SMS:[/cyan] {text[:80]}...")
    clf = SmishingClassifier()
    result = clf.classify(text, sender_number=sender)
    _print_result(result, module="sms")
    if result.get("urls_found"):
        console.print(f"[yellow]URLs found:[/yellow] {', '.join(result['urls_found'])}")
    console.print(f"[yellow]Urgency score:[/yellow] {result.get('urgency_score', 0)}/100")


@cli.command("train")
@click.argument("module", type=click.Choice(["smishing", "web"]))
@click.option("--epochs", default=3, show_default=True)
@click.option("--batch-size", default=16, show_default=True)
def train(module: str, epochs: int, batch_size: int):
    """Train or fine-tune a detection model."""
    if module == "smishing":
        console.print("[bold]Training smishing model (IndoBERT fine-tune)...[/bold]")
        script = "scripts/train_smishing.py"
    else:
        console.print("[bold]Training web phishing model (RF + XGB)...[/bold]")
        script = "scripts/train_web.py"

    subprocess.run(
        [sys.executable, script, f"--epochs={epochs}", f"--batch-size={batch_size}"],
        check=True,
    )


@cli.command("dashboard")
@click.option("--port", default=8501, show_default=True)
def dashboard(port: int):
    """Launch Streamlit dashboard."""
    console.print(f"[bold green]Starting dashboard on port {port}[/bold green]")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", "dashboard/streamlit_app.py",
         f"--server.port={port}"],
        check=True,
    )


def _print_result(result: dict, module: str) -> None:
    label = result["label"]
    confidence = result.get("confidence", 0)
    color = {"safe": "green", "suspicious": "yellow", "malicious": "red"}.get(label, "white")

    table = Table(title=f"[bold]{module.upper()} Classification Result[/bold]", show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("Label", f"[{color}]{label.upper()}[/{color}]")
    table.add_row("Confidence", f"{confidence:.1%}")
    console.print(table)

    if result.get("reasons"):
        console.print("\n[bold]Reasons:[/bold]")
        for r in result["reasons"]:
            console.print(f"  • {r}")


if __name__ == "__main__":
    cli()
