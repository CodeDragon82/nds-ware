import os

import click
from parsers.nds import Nds

CODE_FOLDER = "code"
FILES_FOLDER = "files"

file_index = 0


@click.group()
def cli() -> None:
    """
    Extracts data from key sections of the NDS ROM such as game code and files.
    """


def extract_directory(nds: Nds, directory: Nds.Directory, output_dir: str) -> None:
    global file_index

    for file in reversed(directory.content.files):
        if file.flag.is_directory:
            new_output_dir = os.path.join(output_dir, file.name)
            os.makedirs(new_output_dir, exist_ok=True)

            next_directory_index = file.directory_id & 0xFF
            next_directory = nds.file_name_table.directories[next_directory_index]
            extract_directory(nds, next_directory, new_output_dir)
        else:
            file_path = os.path.join(output_dir, file.name)
            file_data = nds.files[file_index].data
            open(file_path, "wb").write(file_data)
            file_index -= 1


def extract_files(nds: Nds, output_dir: str) -> None:
    global file_index
    file_index = len(nds.files) - 1

    root = nds.file_name_table.directories[0]
    extract_directory(nds, root, output_dir)


def extract_code(nds: Nds, output_dir: str) -> None:
    code_files = [
        ("arm7", nds.arm7),
        ("arm7i", nds.arm7i),
        ("arm9", nds.arm9),
        ("arm9i", nds.arm9i),
    ]

    for file_name, code in code_files:
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(code.data)

    extract_overlays(nds.arm7_overlays, os.path.join(output_dir, "arm7_overlays"))
    extract_overlays(nds.arm9_overlays, os.path.join(output_dir, "arm9_overlays"))


def extract_overlays(overlays: list[Nds.Overlay], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    for i in range(len(overlays)):
        overlay_code = overlays[i].data
        file_name = str(i)
        file_path = os.path.join(output_dir, file_name)
        open(file_path, "wb").write(overlay_code)


@cli.command(help="Extracts data from key sections of the NDS ROM.")
@click.argument("nds_file", type=str)
@click.argument("output_dir", type=str)
def extract(nds_file: str, output_dir: str) -> None:
    nds = Nds.from_file(nds_file)

    code_dir = os.path.join(output_dir, CODE_FOLDER)
    files_dir = os.path.join(output_dir, FILES_FOLDER)

    os.makedirs(code_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)

    extract_files(nds, files_dir)
    extract_code(nds, code_dir)


def is_dsi(nds: Nds) -> bool:
    """Checks the `unit_code` in the ROM header to determine if it includes DSi-specific data sections."""
    return nds.header.unit_code.value != 0


@cli.command(help="Display basic information about a NDS ROM.")
@click.argument("nds_file", type=str)
def info(nds_file: str) -> None:
    nds = Nds.from_file(nds_file)

    info = [
        ("Game Title", nds.header.game_title),
        ("Maker Code", nds.header.maker_code),
        ("Unit Code", f"{nds.header.unit_code.name} ({nds.header.unit_code.value})"),
        ("Encryption Seed", nds.header.encryption_seed),
        ("Device Capacity", nds.header.device_capacity),
        ("Game Revision", nds.header.game_revision),
        ("ROM Version", nds.header.rom_version),
        ("Internal Flags", nds.header.internal_flags),
        ("Normal Card Control Register Settings", nds.header.normal_card_control_register_settings),
        ("Secure Card Control Register Settings", nds.header.secure_card_control_register_settings),
        ("Secure Disable", nds.header.secure_disable),
    ]

    for name, value in info:
        print(f"{name:40} {value}")


def log_section(name: str, info: Nds.FatEntry | Nds.SectionInfo | Nds.CodeSectionInfo) -> tuple[int, int, str]:
    """Converts section information into a common format: `(start_offset, end_offset, name)`"""
    if isinstance(info, Nds.FatEntry):
        return info.start_offset, info.end_offset, name

    return info.offset, info.offset + info.size, name


@cli.command(help="List the data sections within a NDS ROM.")
@click.argument("nds_file", type=str)
def sections(nds_file: str) -> None:
    nds = Nds.from_file(nds_file)

    data_sections = [
        (0x0, 0x4000, "Header"),
        log_section("ARM9 Code", nds.header.arm9),
        log_section("ARM9 Overlay", nds.header.arm9_overlay),
        log_section("ARM7 Code", nds.header.arm7),
        log_section("ARM7 Overlay", nds.header.arm7_overlay),
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
