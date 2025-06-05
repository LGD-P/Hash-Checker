from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
import datetime
from const import RESPONSE_EXEMPLE



class ReportDisplay:
    def __init__(self, response_data):
        self.response = response_data
        self.c = Console(record=True)

    def format_timestamp(self, ts):
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def display_basic_info(self):
        data = self.response['data']
        attrs = data['attributes']
        table = Table(show_header=False, box=box.SQUARE)
        table.add_column("Attribute", style="bold cyan")
        table.add_column("Value", style="grey35")

        table.add_row("File Hash:", f"[bold magenta]{data['id']}[/bold magenta]")
        table.add_row("File Type:", f"[bold green]{data['type']}[/bold green]")
        size = attrs['size']
        table.add_row("File Size:", f"[bold yellow]{size} Ko[/bold yellow]")
        first_sub = self.format_timestamp(attrs['first_submission_date'])
        last_sub = self.format_timestamp(attrs['last_submission_date'])
        table.add_row("First Submission:", f"[bold cyan]{first_sub}[/bold cyan]")
        table.add_row("Last Submission:", f"[bold cyan]{last_sub}[/bold cyan]")
        total_sub = attrs['times_submitted']
        table.add_row("Total Submitted:", f"[bold magenta]{total_sub}[/bold magenta]")
        known_names = attrs['names']
        table.add_row("Known names:", f"[bright_black]{', '.join(known_names)}[/bright_black]")

        self.c.print(Panel(table, title="[bold cyan]BASIC INFO[/bold cyan]", border_style="bright_blue", box=box.ROUNDED))

    def display_analysis_stats(self):
        analysis_stats = self.response['data']['attributes']['last_analysis_stats']
        total_vendors = analysis_stats['malicious'] + analysis_stats['undetected']
        table = Table(show_header=False, box=box.SQUARE)
        table.add_column("Attribute", style="bold yellow")
        table.add_column("Value", style="grey35")

        table.add_row(
            "Last Stat Analyze:",
            f"[bold yellow]{analysis_stats['malicious']}/{total_vendors}[/bold yellow] [bright_black]security vendors flagged this file as malicious[/bright_black]"
        )
        table.add_row("Suspicious:", f"[bold red]{analysis_stats['suspicious']}[/bold red]")
        table.add_row("Undetected:", f"[bold green]{analysis_stats['undetected']}[/bold green]")
        table.add_row("Harmless:", f"[bold green]{analysis_stats['harmless']}[/bold green]")
        table.add_row("Timeout:", f"[bold yellow]{analysis_stats['timeout']}[/bold yellow]")
        table.add_row("Confirmed-timeout:", f"[bold yellow]{analysis_stats['confirmed-timeout']}[/bold yellow]")
        table.add_row("Failure:", f"[bold red]{analysis_stats['failure']}[/bold red]")
        table.add_row("Type-unsupported:", f"[bold magenta]{analysis_stats['type-unsupported']}[/bold magenta]")

        self.c.print(Panel(table, title="[bold yellow]BASIC RESULT FROM ANALYSE[/bold yellow]", border_style="yellow", box=box.ROUNDED))

    def display_sources(self):
        sources_data = self.response['data']['attributes']['last_analysis_results']
        total_vendors = len(sources_data)
        table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("N°", style="bold", width=4)
        table.add_column("Vendor", style="bold")
        table.add_column("Engine Name", style="grey35")
        table.add_column("Category", style="grey35")
        table.add_column("Result", style="grey35")

        for idx, (key, value) in enumerate(sources_data.items(), start=1):
            reverse_num = total_vendors - idx + 1
            engine_name = value.get('engine_name', 'N/A')
            category = value.get('category', 'N/A')
            result = value.get('result', 'N/A')
            table.add_row(str(reverse_num), key, engine_name, category, result)

        self.c.print(Panel(table, title="[bold magenta]SOURCES FROM ANALYSE[/bold magenta]", border_style="magenta", box=box.ROUNDED))

    def display_threat_info(self):
        threats = self.response['data']['attributes']['popular_threat_classification']
        table = Table(show_header=False, box=box.SQUARE)
        table.add_column("Attribute", style="bold red")
        table.add_column("Value", style="grey35")
        table.add_row("Suggested_threat_label:", threats['suggested_threat_label'])
        table.add_row("popular_threat_name:", ', '.join([item['value'] for item in threats['popular_threat_name']]))
        table.add_row("popular_threat_category:", ', '.join([item['value'] for item in threats['popular_threat_category']]))
        self.c.print(Panel(table, title="[bold red]THREAT INFO[/bold red]", border_style="red", box=box.ROUNDED))

    def display_technical_info(self):
        elf_info = self.response['data']['attributes']['elf_info']
        tech_table = Table(show_header=False, box=box.SQUARE)
        tech_table.add_column("Attribute", style="bold dark_goldenrod")
        tech_table.add_column("Details", style="grey35")
        tech_table.add_row("Header:", str(elf_info['header']))
        tech_table.add_row("Shared_libraries:", ', '.join(elf_info['shared_libraries']))
        tech_table.add_row("Export_list:", ', '.join([item['name'] for item in elf_info['export_list']]))
        tech_table.add_row("Import_list:", ', '.join([item['name'] for item in elf_info['import_list']]))
        tech_table.add_row("Section_list:", ', '.join([item['name'] for item in elf_info['section_list']]))
        tech_table.add_row("Segment_list:", ', '.join([item['segment_type'] for item in elf_info['segment_list']]))
        self.c.print(Panel(tech_table, title="[bold dark_goldenrod]TECHNICAL INFO[/bold dark_goldenrod]", border_style="gold3", box=box.ROUNDED))

    def display_miscellaneous(self):
        attributes = self.response['data']['attributes']
        misc_table = Table(show_header=False, box=box.SQUARE)
        misc_table.add_column("Attribute", style="bold blue")
        misc_table.add_column("Details", style="grey35")
        misc_table.add_row("Tags:", ', '.join(attributes['tags']))
        misc_table.add_row("Ssdeep:", attributes['ssdeep'])
        misc_table.add_row("Tlsh:", attributes['tlsh'])
        misc_table.add_row("Crowdsourced_yara_results:", str(attributes['crowdsourced_yara_results']))
        misc_table.add_row("Detectiteasy:", str(attributes['detectiteasy']))
        misc_table.add_row("Trid:", str(attributes['trid']))
        self.c.print(Panel(misc_table, title="[bold blue]MISCELLANEOUS[/bold blue]", border_style="blue", box=box.ROUNDED))




    def show_full_report(self):
        data = self.response['data']
        self.display_basic_info()
        self.display_analysis_stats()
        self.display_sources()
        self.display_threat_info()
        self.display_technical_info()
        self.display_miscellaneous()
        self.c.save_html(f"report_{data['id']}.html")





#report = ReportDisplay(RESPONSE_EXEMPLE)
#report.show_full_report()