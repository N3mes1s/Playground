"""Terminal display utilities using Rich."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()


def print_sessions_table(sessions: list[dict]) -> None:
    table = Table(title="Sessions")
    table.add_column("Provider", style="cyan")
    table.add_column("Session ID", style="green")
    table.add_column("Working Dir", style="yellow")
    table.add_column("Started", style="magenta")

    for s in sessions:
        table.add_row(
            str(s.get("provider", "?")),
            str(s.get("session_id", "?"))[:12] + "...",
            str(s.get("cwd", "?")),
            str(s.get("started_at", "?")),
        )

    console.print(table)


def print_bundle_info(manifest: dict) -> None:
    panel = Panel.fit(
        f"[bold]Provider:[/] {manifest.get('provider', '?')}\n"
        f"[bold]Session:[/] {manifest.get('session_id', '?')}\n"
        f"[bold]Source:[/] {manifest.get('source_hostname', '?')} ({manifest.get('source_platform', '?')})\n"
        f"[bold]CWD:[/] {manifest.get('source_cwd', '?')}\n"
        f"[bold]Created:[/] {manifest.get('created_at', '?')}\n"
        f"[bold]Encrypted:[/] {manifest.get('encrypted', False)}\n"
        f"[bold]Components:[/] {', '.join(manifest.get('components', []))}",
        title="Bundle Info",
    )
    console.print(panel)


def success(msg: str) -> None:
    console.print(f"[bold green]{msg}[/]")


def warning(msg: str) -> None:
    console.print(f"[bold yellow]WARNING: {msg}[/]")


def error(msg: str) -> None:
    console.print(f"[bold red]ERROR: {msg}[/]")


def info(msg: str) -> None:
    console.print(f"[dim]{msg}[/]")


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    )
