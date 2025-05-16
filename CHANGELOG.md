# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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