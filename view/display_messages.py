import os
from typing import Dict, List, Any
from rich.text import Text
from rich.align import Align
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from pathlib import Path
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn

from logic.const import ALGORITHM_STRENGTH

c = Console()

class ErrorMessage:

    @staticmethod
    def display_file_error_file_in_cli(path: Path):
        if not path.exists():
            return c.print(Panel.fit(Text.from_markup(f"[bold blue1]Exist Error: [/bold blue1] [bold red]The path '[bold yellow]{path}[/bold yellow]' does not exist.[/bold red]")))
        if not path.is_file() or path.is_dir():
            return  c.print(Panel.fit(Text.from_markup(f"[bold blue1]is Dir Error: [/bold blue1] [bold red]The path '[bold yellow]{path}[/bold yellow]' is not a file.[/bold red]")))
        if not os.access(path, os.R_OK):
            return  c.print(Panel.fit(Text.from_markup(f"[bold blue1]Permission Error: [/bold blue1] [bold red]No read permission for the file '[bold yellow]{path}[/bold yellow]'.[/bold red]")))
        return False

    @staticmethod
    def display_path_is_not_file(path: Path):
        if not path.is_file():
            return c.print(Panel.fit(Text.from_markup(
                f"[bold blue1]File Error: [/bold blue1] [bold red]The path '[bold yellow]{path}[/bold yellow]' is not a file.[/bold red]")))

    @staticmethod
    def display_path_is_file(path: Path):
            return c.print(Panel.fit(Text.from_markup(
                f"[bold blue1]File Error: [/bold blue1] [bold red]{path}[/bold red][bold yellow]' is a file.[/bold yellow]")))

    @staticmethod
    def display_error_virus_total(response: Dict[str, Any]):
        if response['error']['code'] == "NotFoundError":
            return c.print(Panel.fit(Text.from_markup(
                f"[bold green1]Nothing Found : [/bold green1] [bold gold1] {response["error"]["message"]}[/bold gold1]")))
        if response['error']['code'] == "BadRequestError":
            return c.print(Panel.fit(Text.from_markup(
                f"[bold red1] {response['error']['code']} : [/bold red1] [bold red] {response["error"]["message"]}[/bold red]")))

class AnswerMessages:

    @staticmethod
    def display_hash_from_file_or_string(result: Dict[str, str]) -> None:
        table = Table(title="[bold cyan]Hash Algorithm Strength Hierarchy[/bold cyan]", show_header=True, header_style="bold magenta")
        table.add_column("Algorithm", style="green")
        table.add_column("Level", style="dim", width=15)
        table.add_column("Hash", style="yellow")

        for level, hash_value in result.items():
            strength = ALGORITHM_STRENGTH.get(level, ('Unknown', 'white'))
            table.add_row(level,f"[{strength[1]}]{strength[0]}[/{strength[1]}]",  hash_value)

        c.print(table)

    @staticmethod
    def display_compare_hash_to_string(result: List) -> None:
        if result and len(result) == 3:
            c.print(Panel.fit(Text.from_markup(f"[bold green]{result[0]}[/bold green] is a [bold blue]{result[1]}[/bold blue] algorithm matching with [bold yellow]{result[2]}[/bold yellow]")))
        else:
            c.print(Panel.fit(Text.from_markup("[bold red]Your string does not match any of our algorithms.[/bold red]")))

    @staticmethod
    def display_compare_hash_to_file(result: List) -> None:
        if result and len(result) == 3:
            c.print(Panel.fit(Text.from_markup(f"[bold green]{result[0]}[/bold green] is a [bold blue]{result[1]}[/bold blue] algorithm matching with [bold yellow]{result[2]}[/bold yellow]")))
        else:
            c.print(Panel.fit(Text.from_markup("[bold red]Your file does not match any of our algorithms.[/bold red]")))

    @staticmethod
    def display_duplicate_files(duplicates: Dict[Any, list]):
        for hash, paths in duplicates.items():
            table = Table(show_header=False, box=box.SQUARE, border_style='red1')
            table.add_column("Path")
            table.add_column("Number")

            for idx, path in enumerate(paths, start=1):
                table.add_row(path, str(idx))

            centered_table = Align.center(table)

            c.print(
                Panel(centered_table, title=f"[bold cyan]Hash: {hash}[/bold cyan]", border_style="bright_blue",
                      box=box.ROUNDED)
            )


    @staticmethod
    def progress_bar_scanning_duplicate_files() -> Progress:
        progress_bar = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            transient=True,
        )
        return progress_bar