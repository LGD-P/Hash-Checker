from typing import Dict, List, Any
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from pathlib import Path
import os
from  const import ALGORITHM_STRENGTH
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
