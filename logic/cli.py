import questionary
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory

from .const import CYBER_STYLE_TOOLKIT
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .const import  CYBER_STYLE_QUESTIONARY

c = Console()

class Cli:

    @staticmethod
    def main_menu():
        c.print(Panel.fit(Text.from_markup("[bold cyan]What would you like to do?[/bold cyan]"), border_style="cyan"))
        return questionary.select(
            "",
            choices=[
                "Generate hash from a file",
                "Generate hash from a string",
                "Compare hash to a string",
                "Compare hash to a file",
                "Scan a Hash with Virus-Total",
                "Select file to check duplication",
                "Global check directories for Duplicate Files",
                "Exit"
            ],
            style=CYBER_STYLE_QUESTIONARY
        ).ask()


    @staticmethod
    def get_file_path():
        c.print(Panel.fit(Text.from_markup("[bold cyan]Please enter the file path:[/bold cyan]"), border_style="cyan"))

        completer = PathCompleter()
        file_path = prompt(
            "",
            completer=completer,
            style=CYBER_STYLE_TOOLKIT,
            auto_suggest=AutoSuggestFromHistory(),
            history=FileHistory('../.file_path_history')
        )

        return file_path

    @staticmethod
    def get_dir_path():
        c.print(Panel.fit(Text.from_markup("[bold cyan]Please enter the dir path:[/bold cyan]"), border_style="cyan"))

        completer = PathCompleter()
        file_path = prompt(
            "",
            completer=completer,
            style=CYBER_STYLE_TOOLKIT,
            auto_suggest=AutoSuggestFromHistory(),
            history=FileHistory('../.file_path_history')
        )

        return file_path



    @staticmethod
    def get_string():
        c.print(Panel.fit(Text.from_markup("[bold cyan]Please enter the string:[/bold cyan]"), border_style="cyan"))
        return questionary.text("").ask()

    @staticmethod
    def get_hash():
        c.print(Panel.fit(Text.from_markup("[bold cyan]Please enter the hash to compare:[/bold cyan]"), border_style="cyan"))
        return questionary.text("").ask()

    @staticmethod
    def get_hash_to_scan():
        c.print(Panel.fit(Text.from_markup("[bold cyan]Please enter the hash you want to scan:[/bold cyan]"),
                          border_style="cyan"))
        return questionary.text("").ask()



