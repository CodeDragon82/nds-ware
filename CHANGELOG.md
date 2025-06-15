# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-15

### Added

- `extract_graphics`, a new Python-based command-line tool, which can reconstruct PNG/BMP images from NCGR and NCLR files (#38).
- Kaitai definition and parser for the G2D binary file format, which includes the NCGR and NCLR files (#38).
- View the file system inside an NDS ROM within Ghidra (#37).

### Fixed

- Ghidra loader now assigns the correct permissions to regions in the memory map (#35).

## [1.0.0] - 2025-05-16

### Added

- A Ghidra extension that:
    - Detects if a given binary is an NDS ROM.
    - Loads the ARM9 main code and overlays sections into memory.
    - Sets up the other uninitialised blocks in the memory map.
- Two Python-based command-line tools:
    - `extract_nds`, which extracts files and code sections from a given NDS ROM (`.nds`).
    - `extract_narc`, which extracts files from a given Nintendo Archive (`.narc`) file.
- Kaitai definitions and parsers for the NDS and NARC file formats.