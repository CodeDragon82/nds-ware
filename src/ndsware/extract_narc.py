"""
A tool for extracting files from a Nintendo Archive (NARC).
"""

import os

import click
from kaitaistruct import KaitaiStructError

from ndsware.parsers.narc import Narc


@click.group()
def cli() -> None:
    """Extracts files from a Nintendo Archive (NARC)."""


@cli.command(help="Count the number of files in a Nintendo Archive.")
@click.argument("narc_file")
def count(narc_file: str) -> None:
    """Counts the number of files in a NARC."""
    narc = Narc.from_file(narc_file)

    file_count = len(narc.file_section.data.files)

    print(f"{file_count} files")


def list_directory(
    fnt: Narc.Btnf,
    directory: Narc.Directory,
    depth: int,
    max_depth: int,
    show_option: str,
) -> None:
    """Recursively loops through the FNT and prints out the directory structure of the archive."""
    for file in reversed(directory.content.files):
        if show_option in ["directories", "all"]:
            indent = depth * "  " + "-"
        else:
            indent = "-"

        if file.flag.is_directory:
            if show_option in ["directories", "all"]:
                print(f"{indent} {file.name} (DIR)")

            next_directory_index = file.directory_id & 0xFFF
            next_directory = fnt.directories[next_directory_index]

            if depth < max_depth or max_depth == -1:
                list_directory(fnt, next_directory, depth + 1, max_depth, show_option)
        elif show_option in ["files", "all"]:
            print(f"{indent} {file.name}")


@cli.command("list", help="Show files and folders within a Nintendo Archive.")
@click.argument("narc_file")
@click.option(
    "-d",
    "--max-depth",
    type=int,
    default=-1,
    help="Displays files and folders up to N levels deep.",
)
@click.option(
    "--directories",
    "show_option",
    flag_value="directories",
    help="Only show directory structure.",
)
@click.option(
    "--files",
    "show_option",
    flag_value="files",
    help="Only show files; ignore directory structure.",
)
@click.option(
    "--all",
    "show_option",
    flag_value="all",
    default=True,
    help="Show files and directory structure.",
)
def list_archive(narc_file: str, max_depth: int, show_option: str) -> None:
    """Displays files and folders within a Nintendo Archive (NARC)."""
    narc = Narc.from_file(narc_file)

    fnt = narc.file_name_table.data

    list_directory(fnt, fnt.directories[0], 0, max_depth, show_option)


def extract_directory(
    files: list[Narc.File],
    fnt: Narc.Btnf,
    directory: Narc.Directory,
    file_index: int,
    output_dir: str,
) -> int:
    """
    Extracts all files and sub-directories in a given `directory`. Directory
    structure and file names are extracted from the `fnt` (file name table) and
    mapped to the list of `files` data.

    This function is called recursively (via depth-first search) until all
    sub-directories are extracted.
    """
    os.makedirs(output_dir, exist_ok=True)

    for file in reversed(directory.content.files):
        if file.flag.is_directory:
            new_output_dir = os.path.join(output_dir, file.name)

            next_directory_index = file.directory_id & 0xFFF
            next_directory = fnt.directories[next_directory_index]
            file_index = extract_directory(files, fnt, next_directory, file_index, new_output_dir)
        else:
            file_path = os.path.join(output_dir, file.name)
            file_data = files[file_index].data
            open(file_path, "wb").write(file_data)
            file_index -= 1

    return file_index


def parse_narc_file(file_path: str) -> Narc | None:
    """Attempts to parse a file with the NARC Kaitai parser."""

    try:
        return Narc.from_file(file_path)
    except KaitaiStructError:
        return None
    except Exception as e:
        print(f"ERROR: failed parsing {file_path} ({e})")
        return None


def extract(narc: Narc, output_dir: str) -> None:
    """
    Extracts files archived in the `narc_file` and writes them to the
    `output_dir`.

    The directory structure and file names are extracted from the FNT (file
    name table).
    """
    files = narc.file_section.data.files
    fnt = narc.file_name_table.data

    file_index = len(files) - 1

    # Extract files mapped in the FNT.
    if narc.file_name_table.size > 16:
        file_index = extract_directory(files, fnt, fnt.directories[0], file_index, output_dir)

    # Extract files NOT mapped in the FNT.
    os.makedirs(output_dir, exist_ok=True)
    while file_index > -1:
        file_path = os.path.join(output_dir, str(file_index))
        file_data = files[file_index].data
        open(file_path, "wb").write(file_data)
        file_index -= 1


@cli.command("extract", help="Extract files from a Nintendo Archive.")
@click.argument("narc_file")
@click.argument("output_dir")
def extract_single(narc_file: str, output_dir: str) -> None:
    """Extracts a single NARC archive file."""
    narc = parse_narc_file(narc_file)
    if narc is not None:
        print(f"Extracted {narc_file}...")
        extract(narc, output_dir)
        print("Done!")
    else:
        print(f"{narc_file} can't be parsed as a NARC file.")


@cli.command(help="Extract all NARC files in a given directory.")
@click.argument("in_dir")
@click.option("-r", "--recursive", is_flag=True, default=False)
def extract_all(in_dir: str, recursive: bool) -> None:
    """Extracts all NARC archive files in a given directory."""
    for directory_path, _, filenames in os.walk(in_dir):
        for filename in filenames:
            in_file = os.path.join(directory_path, filename)
            out_directory = os.path.join(directory_path, filename + ".out")

            narc = parse_narc_file(in_file)
            if narc is not None:
                extract(narc, out_directory)
                print(f"EXTRACTED {in_file}")

        if not recursive:
            break


if __name__ == "__main__":
    cli()
