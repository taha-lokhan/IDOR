"""
CLI entrypoint for the IDOR tool.
"""
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import load_config
from .models import ScanConfig, ScanResult
from .scanner import run_scan
from .reporter import generate_reports, open_report_dashboard

console = Console()


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Insecure Direct Object Reference (IDOR) scanner."""
    pass


@main.command("scan")
@click.argument("url", type=str)
@click.option("--id-range", nargs=2, type=int, required=True, help="Start and end of ID range (e.g., 1 100)")
@click.option("--header", "-H", multiple=True, type=str, help="HTTP header (e.g., 'Authorization: Bearer TOKEN')")
@click.option("--concurrency", "-c", type=int, default=5, help="Number of concurrent requests")
def cmd_scan(
    url: str,
    id_range: List[int],
    header: Optional[List[str]],
    concurrency: int,
) -> None:
    """
    Fuzz an IDOR endpoint by substituting {id} in the URL.
    """
    start, end = id_range
    headers = {}
    for h in header or []:
        if ":" not in h:
            console.print(f"[bold red]Invalid header format: {h}[/bold red]")
            raise click.BadParameter(f"Headers must be in KEY: VALUE format: {h}")
        key, value = h.split(":", 1)
        headers[key.strip()] = value.strip()

    if "{id}" not in url:
        console.print(
            "[bold red]URL must contain '{id}' placeholder[/bold red]"
        )
        raise click.BadParameter("URL must contain '{id}' placeholder")

    config = ScanConfig(
        target=url,
        id_start=start,
        id_end=end,
        headers=headers,
        concurrency=concurrency,
    )

    console.print(
        f"[bold]Scanning:[/bold] {config.target} (ID {config.id_start} → {config.id_end})"
    )
    results, stats = run_scan(config)

    table = Table(title="Scan Results")
    table.add_column("ID", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Body len", justify="right")
    table.add_column("Diff", justify="right")

    for item in results:
        diff = item.diff_status or item.diff_len
        table.add_row(
            str(item.id),
            str(item.status),
            str(item.body_len),
            "-" if diff is None else "Y" if diff else "N",
        )

    console.print(table)

    generate_reports(results, stats, url)


@main.command("scan-config")
@click.argument("config_path", type=click.Path(exists=True, dir_okay=False))
def cmd_scan_from_config(config_path: str) -> None:
    """
    Run a scan from a YAML configuration file.
    """
    config = load_config(config_path)

    console.print(
        f"[bold]Using config:[/bold] {config_path}"
    )
    console.print(
        f"[bold]Target:[/bold] {config.target}"
    )
    console.print(
        f"[bold]ID range:[/bold] {config.id_start} → {config.id_end}"
    )
    console.print(
        f"[bold]Concurrency:[/bold] {config.concurrency}"
    )

    results, stats = run_scan(config)

    table = Table(title="Scan Results")
    table.add_column("ID", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Body len", justify="right")
    table.add_column("Diff", justify="right")

    for item in results:
        diff = item.diff_status or item.diff_len
        table.add_row(
            str(item.id),
            str(item.status),
            str(item.body_len),
            "-" if diff is None else "Y" if diff else "N",
        )

    console.print(table)

    generate_reports(results, stats, config.target)


@main.command("dashboard")
def cmd_dashboard() -> None:
    """
    Open the latest HTML dashboard report in the browser.
    """
    open_report_dashboard()
