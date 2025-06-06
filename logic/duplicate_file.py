import os
import hashlib
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any
from rich.console import Console

from view.display_messages import AnswerMessages

c = Console()

class DuplicationTracker:
    @staticmethod
    def single_hash_calculator(file_path: Path):
        sha3_512_hash = hashlib.sha3_512()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha3_512_hash.update(byte_block)
        return sha3_512_hash.hexdigest()


    @staticmethod
    def report_duplicate_in_txt(duplicates: Dict[Any, list]):
        # Generate the output file name with the current datetime
        output_file = f"scan_report_{datetime.now().strftime('%d-%m-%Y--%H-%M-%S')}.txt"

        # Write duplicates to the output file
        with open(output_file, "w") as f:
            for hash, paths in duplicates.items():
                f.write(f"Hash: {hash}\n")
                for path in paths:
                    f.write(f"  {path}\n")
                f.write("\n")


    @staticmethod
    def number_of_file_to_check(dir_path: Path) -> list:
        files_list = []

        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                files_list.append(file_path)
        return files_list

    @staticmethod
    def parse_directories(dir_path: Path, hash_reference: str = None):
        hash_to_files = defaultdict(list)
        files_list = DuplicationTracker.number_of_file_to_check(dir_path)
        duplicates_found = 0
        total_files = len(files_list)

        with AnswerMessages.progress_bar_scanning_duplicate_files() as progress:
            task = progress.add_task("Scanning files...", total=total_files, duplicates=0)

            for idx, file_path in enumerate(files_list, 1):
                # Calculate hash
                file_hash = DuplicationTracker.single_hash_calculator(file_path)
                if file_hash is not None:
                    if hash_reference is None:
                        hash_to_files[file_hash].append(file_path)
                    else:
                        if file_hash == hash_reference:
                            hash_to_files[file_hash].append(file_path)

                    # Check if a group of duplicates has been created
                    group = hash_to_files[file_hash]
                    if len(group) == 2:  # when the second file with the same hash is added
                        duplicates_found += 1
                        progress.update(task, duplicates=duplicates_found)

                    progress.update(task, advance=1)
                progress.update(task, completed=total_files)
            progress.stop()

            # Filter to keep only groups with multiple files
            if hash_reference is None:
                duplicates = {hash: paths for hash, paths in hash_to_files.items() if len(paths) > 1}
            else:
                duplicates = {hash_reference: paths for hash, paths in hash_to_files.items() if len(paths) > 1}

            if not duplicates:
                c.print("\n\n[bold blue1]No duplicate files found.[/bold blue1]")
                return

            # Write report in file
            DuplicationTracker.report_duplicate_in_txt(duplicates)


            # Display report in console
            AnswerMessages.display_duplicate_files(duplicates)


