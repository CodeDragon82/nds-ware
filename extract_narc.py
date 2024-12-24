import os

import click
from parsers.narc import Narc

file_index = 0


@click.group()
def cli() -> None:
    """Extracts files from a Nintendo Archive (NARC)."""


@cli.command(help="Count the number of files in a Nintendo Archive.")
@click.argument("narc_file")
def count(narc_file: str) -> None:
    narc = Narc.from_file(narc_file)

    file_count = len(narc.file_section.data.files)

    print(f"{file_count} files")


def extract_directory(
    files: list[Narc.File],
    fnt: Narc.Btnf,
    directory: Narc.Directory,
    output_dir: str,
) -> None:
    global file_index

    os.makedirs(output_dir, exist_ok=True)

    for file in reversed(directory.content.files):
        if file.flag.is_directory:
            new_output_dir = os.path.join(output_dir, file.name)

            next_directory_index = file.directory_id & 0xFF
            next_directory = fnt.directories[next_directory_index]
            extract_directory(files, fnt, next_directory, new_output_dir)
        else:
            file_path = os.path.join(output_dir, file.name)
            file_data = files[file_index].data
            open(file_path, "wb").write(file_data)
            file_index -= 1


@cli.command(help="Extract files from a Nintendo Archive.")
@click.argument("narc_file")  # , help="File path to the NARC file to extract.")
@click.argument(
    "output_dir"
)  # , help="Directory that files are extracted to.")
def extract(narc_file: str, output_dir: str) -> None:
    narc = Narc.from_file(narc_file)

    files = narc.file_section.data.files
    fnt = narc.file_name_table.data

    global file_index
    file_index = len(files) - 1

    extract_directory(files, fnt, fnt.directories[0], output_dir)


if __name__ == "__main__":
    cli()
