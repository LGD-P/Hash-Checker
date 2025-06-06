import questionary
from pathlib import Path
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .virus_total_api import VirusTotal
from .const import CYBER_STYLE_TOOLKIT, CYBER_STYLE_QUESTIONARY
from .duplicate_file import DuplicationTracker
from .hash_checker import HashChecker
from view.display_virus_total_report import ReportDisplay
from view.display_messages import AnswerMessages, ErrorMessage

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

    @staticmethod
    def run():
        try:
            while True:
                choice = Cli.main_menu()
                if choice == "Generate hash from a file":
                    file_path = Path(Cli.get_file_path())
                    hashes = HashChecker.generate_hashes_from_file(file_path)
                    if not hashes:
                        return ErrorMessage.display_file_error_file_in_cli(file_path)
                    else:
                        AnswerMessages.display_hash_from_file_or_string(hashes)

                elif choice == "Generate hash from a string":
                    string = Cli.get_string()
                    hashes = HashChecker.generate_hashes_form_string(string)
                    AnswerMessages.display_hash_from_file_or_string(hashes)

                elif choice == "Compare hash to a string":
                    hash_to_compare = Cli.get_hash()
                    string = Cli.get_string()
                    result = HashChecker.compare_hash_to_string(hash_to_compare, string)
                    AnswerMessages.display_compare_hash_to_string(result)

                elif choice == "Compare hash to a file":
                    hash_to_compare = Cli.get_hash()
                    file_path = Path(Cli.get_file_path())
                    result = HashChecker.compare_hash_to_file(hash_to_compare, file_path)

                    if not result:
                        return ErrorMessage.display_file_error_file_in_cli(file_path)
                    else:
                        AnswerMessages.display_compare_hash_to_file(result)

                elif choice == "Scan a Hash with Virus-Total":
                    hash_to_scan = Cli.get_hash_to_scan()
                    virus_total = VirusTotal(hash_to_scan)
                    scan = virus_total.ask_virus_total()
                    if 'error' in scan:
                        ErrorMessage.display_error_virus_total(scan)
                    else:
                        report = ReportDisplay(scan)
                        report.show_full_report()

                elif choice == "Select file to check duplication":
                    file_path = Path(Cli.get_file_path())
                    if not file_path.is_file():
                        return ErrorMessage.display_path_is_not_file(file_path)
                    hashes = DuplicationTracker.single_hash_calculator(file_path)
                    if not hashes:
                        return ErrorMessage.display_file_error_file_in_cli(file_path)
                    else:
                        dir_path = Path(Cli.get_dir_path())
                        DuplicationTracker.parse_directories(dir_path, hashes)

                elif choice == "Global check directories for Duplicate Files":
                    file_path = Path(Cli.get_file_path())
                    if file_path.is_file():
                        ErrorMessage.display_path_is_file(file_path)
                    else:
                        DuplicationTracker.parse_directories(file_path)

                elif choice == "Exit":
                    break

        except KeyboardInterrupt:
            # Handle Ctrl+C
            c.print("\n[bold red]Exiting... Goodbye![/bold red]")

if __name__ == "__main__":
    Cli.run()
