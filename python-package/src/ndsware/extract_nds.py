"""
A tool for extracting file and code sections from NDS ROM.

Author: CodeDragon82
Data: 04/05/2025
"""

from __future__ import annotations

import os
from typing import Optional

import click
from ndsware.parsers.nds import Nds
from tabulate import tabulate

CODE_FOLDER = "code"
FILES_FOLDER = "files"


class ExploreException(Exception):
    pass


class FileNode:
    file_index = 0

    def __init__(self, name: str, parent: Optional[FileNode]):
        self.name: str = name
        self.parent: Optional[FileNode] = parent
        self.children: list[FileNode] = []
        self.file: Optional[Nds.File] = None

    def add(self, child: FileNode) -> None:
        self.children.append(child)

    def set_file(self, file: Nds.File) -> None:
        self.file = file

    def get_file_data(self) -> bytes:
        if self.file is None:
            raise ExploreException("File doesn't have data.")

        return self.file.data

    def get(self, path: str) -> FileNode:
        if path == "":
            return self

        if path[0] == "/":
            return self.get_root().get(path[1:])

        next_filename, *rest = path.split("/")
        path_end = "/".join(rest)

        if next_filename == ".":
            return self.get(path_end)

        if next_filename == "..":
            if self.parent is None:
                raise ExploreException("Cannot traverse backwards from the root directory.")

            return self.parent.get(path_end)

        for child in self.children:
            if child.name == next_filename:
                return child.get(path_end)

        raise ExploreException(f"`{next_filename}` not found.")

    def get_root(self) -> FileNode:
        if self.parent is None:
            return self

        return self.parent

    def get_folder(self, name: str) -> FileNode:
        target = self.get(name)

        if target.is_directory():
            return target

        raise ExploreException(f"'{name}' is not a directory.")

    def get_path(self) -> str:
        if self.parent is None:
            return "/"

        return self.parent.get_path() + self.name + "/"

    def get_listing(self) -> str:
        if self.is_directory():
            return f"D\t{self.name}"

        info: Nds.FatEntry = self.file.info
        size = info.end_offset - info.start_offset
        return f"_\t{self.name}\t{size} B"

    def get_listings(self, recursive: bool = False, tab: int = 0) -> str:
        listings = ""

        if self.is_directory():
            for child in self.children:
                listings += "\t" * tab + child.get_listing() + "\n"
                if recursive:
                    listings += child.get_listings(recursive, tab + 1)

        return listings

    def extract(self, output_path: str) -> None:
        output_path = os.path.join(output_path, self.name)
        print(output_path)

        if self.is_directory():
            os.makedirs(output_path, exist_ok=True)

            for child in self.children:
                child.extract(output_path)
        else:
            open(output_path, "wb").write(self.get_file_data())

    def is_directory(self) -> bool:
        return self.file is None

    def load(self, nds: Nds, directory: Nds.Directory) -> None:
        file: Nds.FileEntry
        for file in reversed(directory.files[:-1]):
            child_node = FileNode(file.name, self)
            self.add(child_node)

            if file.is_directory:
                next_directory_index = file.directory_id & 0xFFF
                next_directory = nds.file_name_table.directories[next_directory_index]

                child_node.load(nds, next_directory)
            else:
                child_node.set_file(nds.files[FileNode.file_index])
                FileNode.file_index -= 1

    @staticmethod
    def load_file_system(nds: Nds) -> FileNode:
        FileNode.file_index = len(nds.files) - 1

        root_directory = nds.file_name_table.directories[0]
        root_node = FileNode("", None)
        root_node.load(nds, root_directory)

        return root_node


@click.group()
def cli() -> None:
    """
    Extracts data from key sections of the NDS ROM such as game code and files.
    """


@cli.command()
@click.argument("nds_file", type=str)
def explore(nds_file: str) -> None:
    nds = Nds.from_file(nds_file)
    current_directory: FileNode = FileNode.load_file_system(nds)

    while True:
        prompt = f"{nds.header.game_title}:{current_directory.get_path()} > "
        parts = input(prompt).split()
        command = parts[0] if parts else ""
        arguments = parts[1:] if len(parts) > 1 else []

        try:
            current_directory = process_explore_command(command, arguments, current_directory)
        except ExploreException as e:
            print(f"ERROR: {e}")


def process_explore_command(command: str, arguments: list[str], current_directory: FileNode) -> FileNode:
    match command:
        case "ls":
            print(current_directory.get_listings())
        case "lsr":
            print(current_directory.get_listings(recursive=True))
        case "cd":
            current_directory = change_directory(arguments, current_directory)
        case "extract":
            explore_command_extract(arguments, current_directory)
        case "exit":
            raise SystemExit("Goodbye!")
        case _:
            raise ExploreException("Invalid command.")

    return current_directory


def change_directory(arguments: list[str], current_directory: FileNode) -> FileNode:
    if len(arguments) > 0:
        return current_directory.get_folder(arguments[0])

    raise ExploreException("Must specify a directory to change to.")


def explore_command_extract(arguments: list[str], current_directory: FileNode) -> None:
    if len(arguments) == 0:
        raise ExploreException("Must specify an file or folder to extract.")

    if len(arguments) == 1:
        raise ExploreException("Must specify an output directory.")

    target_path = arguments[0]
    output_path = arguments[1]

    target = current_directory.get(target_path)

    target.extract(output_path)


@cli.command(help="Display files/directory structure.")
@click.argument("nds_file", type=str)
def files(nds_file: str) -> None:
    """Displays the file/directory structure of the NDS ROM."""

    nds = Nds.from_file(nds_file)
    root = FileNode.load_file_system(nds)

    print(root.get_listings(recursive=True))


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
        overlay_code = overlay.file.data
        file_name = str(i)
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(overlay_code)


@cli.command(help="Extracts data from key sections of the NDS ROM.")
@click.argument("nds_file", type=str)
@click.argument("output_dir", type=str)
def extract(nds_file: str, output_dir: str) -> None:
    """Extracts extracts file and code sections from the NDS ROM and writes the data to files in the `output_dir`."""

    nds = Nds.from_file(nds_file)
    root = FileNode.load_file_system(nds)

    code_dir = os.path.join(output_dir, CODE_FOLDER)
    files_dir = os.path.join(output_dir, FILES_FOLDER)

    os.makedirs(code_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)

    root.extract(files_dir)
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


def log_section(
    name: str, section_info: Nds.FatEntry | Nds.OverlayEntry | Nds.SectionInfo | Nds.CodeSectionInfo
) -> tuple[int, int, str]:
    """
    Converts section information into a common format: `(start_offset, end_offset, name)`
    """

    if isinstance(section_info, Nds.FatEntry):
        return section_info.start_offset, section_info.end_offset, name

    if isinstance(section_info, Nds.OverlayEntry):
        return section_info.start_address, section_info.end_address, name

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

    for i, entry in enumerate(nds.arm9_overlay_table.entries):
        data_sections.append(log_section(f"ARM9 Overlay {i}", entry))

    for i, entry in enumerate(nds.arm7_overlay_table.entries):
        data_sections.append(log_section(f"ARM7 Overlay {i}", entry))

    data_sections.sort()

    for section in data_sections:
        print(
            f"0x{section[0]:08x} - 0x{section[1]:08x}",
            f"{section[1] - section[0]:10}B\t{section[2]}",
        )


def displays_overlays(overlays: list[Nds.Overlay]) -> None:
    headers = ["ROM Offset", "Index", "Base Address", "BSS", "Static Init", "File ID", "Reserved"]

    rows = []
    for overlay in overlays:
        rows.append(
            [
                f"{hex(overlay.file.info.start_offset)}-{hex(overlay.file.info.end_offset)}",
                overlay.info.index,
                hex(overlay.info.base_address),
                overlay.info.bss_size,
                f"{hex(overlay.info.start_address)}-{hex(overlay.info.end_address)}",
                overlay.info.file_id,
                hex(overlay.info.reserved),
            ]
        )

    print(tabulate(rows, headers=headers, tablefmt="pretty"))


@cli.command(help="Display a table of overlay information from the NDS ROM.")
@click.argument("nds_file", type=str)
def overlays(nds_file: str) -> None:
    """Displays a table of overlay information from the NDS ROM."""
    nds = Nds.from_file(nds_file)

    print("\nARM9 Overlays\n" + "=" * 13)
    displays_overlays(nds.arm9_overlays)

    print("\nARM7 Overlays\n" + "=" * 13)
    displays_overlays(nds.arm7_overlays)


if __name__ == "__main__":
    cli()
