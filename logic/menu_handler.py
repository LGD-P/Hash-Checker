from pathlib import Path
from rich.console import Console
from typing import Dict, Callable

from .virus_total_api import VirusTotal
from .duplicate_file import DuplicationTracker
from .hash_checker import HashChecker
from .cli import Cli
from view.display_virus_total_report import ReportDisplay
from view.display_messages import AnswerMessages, ErrorMessage

c = Console()

class MenuHandler:

    @staticmethod
    def run():
        try:
            while True:
                choice = Cli.main_menu()
                if choice == "Exit":
                    break

                # Dispatch the choice to the appropriate handler
                handler = MenuHandler._get_handler(choice)
                if handler:
                    handler()
                else:
                    print(f"Unknown choice: {choice}")

        except KeyboardInterrupt:
            # Handle Ctrl+C
            c.print("\n[bold red]Exiting... Goodbye![/bold red]")

    @staticmethod
    def _get_handler(choice: str) -> Callable:
        handlers: Dict[str, Callable] = {
            "Generate hash from a file": MenuHandler.handle_generate_hash_from_file,
            "Generate hash from a string": MenuHandler.handle_generate_hash_from_string,
            "Compare hash to a string": MenuHandler.handle_compare_hash_to_string,
            "Compare hash to a file": MenuHandler.handle_compare_hash_to_file,
            "Scan a Hash with Virus-Total": MenuHandler.handle_scan_hash_with_virus_total,
            "Select file to check duplication": MenuHandler.handle_select_file_to_check_duplication,
            "Global check directories for Duplicate Files": MenuHandler.handle_global_check_directories_for_duplicate_files
        }
        return handlers.get(choice)



    @staticmethod
    def handle_generate_hash_from_file():
        file_path = Path(Cli.get_file_path())
        hashes = HashChecker.generate_hashes_from_file(file_path)
        if not hashes:
            ErrorMessage.display_file_error_file_in_cli(file_path)
        else:
            AnswerMessages.display_hash_from_file_or_string(hashes)

    @staticmethod
    def handle_generate_hash_from_string():
        string = Cli.get_string()
        hashes = HashChecker.generate_hashes_form_string(string)
        AnswerMessages.display_hash_from_file_or_string(hashes)

    @staticmethod
    def handle_compare_hash_to_string():
        hash_to_compare = Cli.get_hash()
        string = Cli.get_string()
        result = HashChecker.compare_hash_to_string(hash_to_compare, string)
        AnswerMessages.display_compare_hash_to_string(result)

    @staticmethod
    def handle_compare_hash_to_file():
        hash_to_compare = Cli.get_hash()
        file_path = Path(Cli.get_file_path())
        result = HashChecker.compare_hash_to_file(hash_to_compare, file_path)
        if not result:
            ErrorMessage.display_file_error_file_in_cli(file_path)
        else:
            AnswerMessages.display_compare_hash_to_file(result)

    @staticmethod
    def handle_scan_hash_with_virus_total():
        hash_to_scan = Cli.get_hash_to_scan()
        virus_total = VirusTotal(hash_to_scan)
        scan = virus_total.ask_virus_total()
        if 'error' in scan:
            ErrorMessage.display_error_virus_total(scan)
        else:
            report = ReportDisplay(scan)
            report.show_full_report()

    @staticmethod
    def handle_select_file_to_check_duplication():
        file_path = Path(Cli.get_file_path())
        if not file_path.is_file():
            ErrorMessage.display_path_is_not_file(file_path)
            return
        hashes = DuplicationTracker.single_hash_calculator(file_path)
        if not hashes:
            ErrorMessage.display_file_error_file_in_cli(file_path)
        else:
            dir_path = Path(Cli.get_dir_path())
            DuplicationTracker.parse_directories(dir_path, hashes)

    @staticmethod
    def handle_global_check_directories_for_duplicate_files():
        file_path = Path(Cli.get_file_path())
        if file_path.is_file():
            ErrorMessage.display_path_is_file(file_path)
        else:
            DuplicationTracker.parse_directories(file_path)


