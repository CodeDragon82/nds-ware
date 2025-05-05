"""
A tool for extracting file and code sections from NDS ROM.

Author: CodeDragon82
Data: 04/05/2025
"""

import os

import click

from ndsware.parsers.nds import Nds

CODE_FOLDER = "code"
FILES_FOLDER = "files"

file_index = 0


@click.group()
def cli() -> None:
    """
    Extracts data from key sections of the NDS ROM such as game code and files.
    """


@cli.command(help="Display files/directory structure.")
@click.argument("nds_file", type=str)
def files(nds_file: str) -> None:
    """Displays the file/directory structure of the NDS ROM."""

    nds = Nds.from_file(nds_file)

    extract_files(nds, None)


def extract_directory(nds: Nds, directory: Nds.Directory, indent: int, output_dir: str | None) -> None:
    """
    Loops through each entry in a FNT directory.

    If the entry is a file, file data pointed to by the FAT is extracted and written to the new file. The
    name of the new file defined in the entry. Then the `file_index` is then incremented.

    If the entry is a directory, a new directory with the name specified in the entry is created and the
    `extract_directory` is called again of the new directory.
    """
    global file_index

    for file in reversed(directory.files[:-1]):
        if output_dir is None:
            print("\t" * indent + file.name)

        if file.is_directory:
            if output_dir:
                output_dir = os.path.join(output_dir, file.name)
                os.makedirs(output_dir, exist_ok=True)

            next_directory_index = file.directory_id & 0xFFF
            next_directory = nds.file_name_table.directories[next_directory_index]
            extract_directory(nds, next_directory, indent + 1, output_dir)
        else:
            if output_dir:
                file_path = os.path.join(output_dir, file.name)
                file_data = nds.files[file_index].data
                open(file_path, "wb").write(file_data)

            file_index -= 1


def extract_files(nds: Nds, output_dir: str | None) -> None:
    """Fetches the root directory entry in the FNT and calls `extract_directory` on it."""

    global file_index
    file_index = len(nds.files) - 1

    root = nds.file_name_table.directories[0]
    extract_directory(nds, root, 0, output_dir)


def extract_code(nds: Nds, output_dir: str) -> None:
    """Extract and write each code section to a file, including the overlay sections."""

    code_files = [
        ("arm7", nds.arm7),
        ("arm9", nds.arm9),
    ]
    if is_dsi(nds):
        code_files += [
            ("arm7i", nds.arm7i),
            ("arm9i", nds.arm9i),
        ]

    for file_name, code in code_files:
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(code.data)

    extract_overlays(nds.arm7_overlays, os.path.join(output_dir, "arm7_overlays"))
    extract_overlays(nds.arm9_overlays, os.path.join(output_dir, "arm9_overlays"))


def extract_overlays(overlays: list[Nds.Overlay], output_dir: str) -> None:
    """Extracts the overlay section data from the NDS ROM, writing each overlay to a new file in `output_dir`."""

    os.makedirs(output_dir, exist_ok=True)

    for i, overlay in enumerate(overlays):
        overlay_code = overlay.data
        file_name = str(i)
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(overlay_code)


@cli.command(help="Extracts data from key sections of the NDS ROM.")
@click.argument("nds_file", type=str)
@click.argument("output_dir", type=str)
def extract(nds_file: str, output_dir: str) -> None:
    """Extracts extracts file and code sections from the NDS ROM and writes the data to files in the `output_dir`."""

    nds = Nds.from_file(nds_file)

    code_dir = os.path.join(output_dir, CODE_FOLDER)
    files_dir = os.path.join(output_dir, FILES_FOLDER)

    os.makedirs(code_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)

    extract_files(nds, files_dir)
    extract_code(nds, code_dir)


def is_dsi(nds: Nds) -> bool:
    """
    Checks the `unit_code` in the ROM header to determine if it includes DSi-specific data sections.
    """

    return nds.header.unit_code.value != 0


@cli.command(help="Display basic information about a NDS ROM.")
@click.argument("nds_file", type=str)
def info(nds_file: str) -> None:
    """Displays header information from the NDS ROM."""

    nds = Nds.from_file(nds_file)

    nds_info = [
        ("Game Title", nds.header.game_title),
        ("Maker Code", nds.header.maker_code),
        (
            "Unit Code",
            f"{nds.header.unit_code.name} ({nds.header.unit_code.value})",
        ),
        ("Encryption Seed", nds.header.encryption_seed),
        ("Device Capacity", nds.header.device_capacity),
        ("Game Revision", nds.header.game_revision),
        ("ROM Version", nds.header.rom_version),
        ("Internal Flags", nds.header.internal_flags),
        (
            "Normal Card Control Register Settings",
            nds.header.normal_card_control_register_settings,
        ),
        (
            "Secure Card Control Register Settings",
            nds.header.secure_card_control_register_settings,
        ),
        ("Secure Disable", nds.header.secure_disable),
    ]

    for name, value in nds_info:
        print(f"{name:40} {value}")


def log_section(name: str, section_info: Nds.FatEntry | Nds.SectionInfo | Nds.CodeSectionInfo) -> tuple[int, int, str]:
    """
    Converts section information into a common format: `(start_offset, end_offset, name)`
    """

    if isinstance(section_info, Nds.FatEntry):
        return section_info.start_offset, section_info.end_offset, name

    return section_info.offset, section_info.offset + section_info.size, name


@cli.command(help="List the data sections within a NDS ROM.")
@click.argument("nds_file", type=str)
def sections(nds_file: str) -> None:
    """Displays the address ranges and names of sections in the NDS ROM."""

    nds = Nds.from_file(nds_file)

    data_sections = [
        (0x0, 0x4000, "Header"),
        log_section("ARM9 Code", nds.header.arm9),
        log_section("ARM9 Overlay Table", nds.header.arm9_overlay),
        log_section("ARM7 Code", nds.header.arm7),
        log_section("ARM7 Overlay Table", nds.header.arm7_overlay),
        log_section("FNT (File Name Table)", nds.header.fnt_info),
        log_section("FAT (File Allocation Table)", nds.header.fat_info),
    ]

    if is_dsi(nds):
        data_sections.append(log_section("ARM9i Code", nds.extended_header.arm9i))
        data_sections.append(log_section("ARM7i Code", nds.extended_header.arm7i))

    for i, entry in enumerate(nds.file_allocation_table):
        data_sections.append(log_section(f"FILE {i}", entry))

    data_sections.sort()

    for section in data_sections:
        print(
            f"0x{section[0]:08x} - 0x{section[1]:08x}",
            f"{section[1] - section[0]:10}B\t{section[2]}",
        )


if __name__ == "__main__":
    cli()
