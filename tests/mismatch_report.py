"""Rendering of PML/CSV mismatches, so that manual comparisons are readable."""

from difflib import SequenceMatcher

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

PML_STYLE = "bold red"
CSV_STYLE = "bold green"


def _records_table(pml_record, csv_record):
    table = Table(title="Records", title_justify="left", header_style="bold")
    table.add_column("Column", style="bold")
    table.add_column("PML", style="red", overflow="fold")
    table.add_column("CSV", style="green", overflow="fold")

    columns = list(pml_record) + [column for column in csv_record if column not in pml_record]
    for column in columns:
        pml_value = str(pml_record.get(column, ""))
        csv_value = str(csv_record.get(column, ""))
        style = None if pml_value == csv_value else "on grey19"
        table.add_row(column, pml_value, csv_value, style=style)

    return table


def _value_diff(pml_value, csv_value):
    """Highlights the parts of the values that only one of them has."""
    pml_text = Text("PML: ", style=PML_STYLE)
    csv_text = Text("CSV: ", style=CSV_STYLE)

    for tag, pml_start, pml_end, csv_start, csv_end in SequenceMatcher(None, pml_value, csv_value).get_opcodes():
        if tag in ("replace", "delete"):
            pml_text.append(pml_value[pml_start:pml_end], style="black on red")
        elif tag == "equal":
            pml_text.append(pml_value[pml_start:pml_end])

        if tag in ("replace", "insert"):
            csv_text.append(csv_value[csv_start:csv_end], style="black on green")
        elif tag == "equal":
            csv_text.append(csv_value[csv_start:csv_end])

    return Group(pml_text, csv_text)


def print_mismatch(event_index, column_name, pml_event, pml_record, csv_record, pml_value, csv_value,
                   console=None):
    """Prints both records in full and a colored diff of the values of the mismatching column."""
    console = console or Console(stderr=True)
    console.print(Panel(
        Group(
            Text(repr(pml_event), style="dim"),
            "",
            _records_table(pml_record, csv_record),
            "",
            _value_diff(pml_value, csv_value),
        ),
        title=f"Event {event_index}, column {column_name} mismatch",
        border_style="yellow",
    ))
