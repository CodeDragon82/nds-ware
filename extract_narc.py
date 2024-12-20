import os

import click
from parsers.narc import Narc

TOOL_DESCRIPTION = "Extracts files for a Nintendo Archive (NARC)."


@click.group()
def cli() -> None:
    """Extracts files for a Nintendo Archive (NARC)."""


@cli.command(help="Extract files from a Nintendo Archive.")
@click.argument("narc_file")  # , help="File path to the NARC file to extract.")
@click.argument(
    "output_dir"
)  # , help="Directory that files are extracted to.")
def extract(narc_file: str, output_dir: str) -> None:
    narc = Narc.from_file(narc_file)

    os.makedirs(output_dir, exist_ok=True)

    for i, file in enumerate(narc.file_section.files):
        file_path = os.path.join(output_dir, str(i))
        open(file_path, "wb").write(file.data)


if __name__ == "__main__":
    cli()
