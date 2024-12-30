# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Nds(KaitaiStruct):

    class UnitCodeEnum(Enum):
        nds = 0
        nds_dsi = 2
        dsi = 3
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = Nds.Header(self._io, self, self._root)
        if self.header.unit_code != Nds.UnitCodeEnum.nds:
            self.extended_header = Nds.ExtendedHeader(self._io, self, self._root)

        self.files = []
        for i in range(len(self.file_allocation_table)):
            self.files.append(Nds.File(self.file_allocation_table[i], self._io, self, self._root))

        self.arm9 = Nds.CodeSection(self.header.arm9, self._io, self, self._root)
        self.arm7 = Nds.CodeSection(self.header.arm7, self._io, self, self._root)
        if self.header.unit_code != Nds.UnitCodeEnum.nds:
            self.arm9i = Nds.CodeSection(self.extended_header.arm9i, self._io, self, self._root)

        if self.header.unit_code != Nds.UnitCodeEnum.nds:
            self.arm7i = Nds.CodeSection(self.extended_header.arm7i, self._io, self, self._root)

        self.arm9_overlays = []
        for i in range(len(self.arm9_overlay_table.entries)):
            self.arm9_overlays.append(Nds.Overlay(self.arm9_overlay_table.entries[i], self._io, self, self._root))

        self.arm7_overlays = []
        for i in range(len(self.arm7_overlay_table.entries)):
            self.arm7_overlays.append(Nds.Overlay(self.arm7_overlay_table.entries[i], self._io, self, self._root))


    class CodeSection(KaitaiStruct):
        def __init__(self, info, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.info = info
            self._read()

        def _read(self):
            pass

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data

            _pos = self._io.pos()
            self._io.seek(self.info.offset)
            self._m_data = self._io.read_bytes(self.info.size)
            self._io.seek(_pos)
            return getattr(self, '_m_data', None)


    class FileNameTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_u4le()
            self.section_size = self._io.read_u2le()
            self.directory_count = self._io.read_u2le()
            self.directory_table = []
            for i in range((self.directory_count - 1)):
                self.directory_table.append(Nds.DirectoryEntry((i + 1), self._io, self, self._root))

            self.directories = []
            for i in range(self.directory_count):
                self.directories.append(Nds.Directory(self._io, self, self._root))



    class OverlayEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.index = self._io.read_u4le()
            self.base_address = self._io.read_u4le()
            self.length = self._io.read_u4le()
            self.bss_size = self._io.read_u4le()
            self.start_address = self._io.read_u4le()
            self.end_address = self._io.read_u4le()
            self.file_id = self._io.read_u4le()
            self.reserved = self._io.read_u4le()


    class Overlay(KaitaiStruct):
        def __init__(self, info, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.info = info
            self._read()

        def _read(self):
            pass

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data

            _pos = self._io.pos()
            self._io.seek(self.info.start_address)
            self._m_data = self._io.read_bytes(self.info.length)
            self._io.seek(_pos)
            return getattr(self, '_m_data', None)


    class DirectoryEntry(KaitaiStruct):
        def __init__(self, id, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.id = id
            self._read()

        def _read(self):
            self.directory_offset = self._io.read_u4le()
            self.first_file_position = self._io.read_u2le()
            self.parent_directory = self._io.read_u2le()


    class String(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.length = self._io.read_u1()
            self.value = (self._io.read_bytes(self.length)).decode(u"ascii")


    class SectionInfo(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u4le()
            self.size = self._io.read_u4le()


    class FatEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.start_offset = self._io.read_u4le()
            self.end_offset = self._io.read_u4le()


    class OverlayTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while not self._io.is_eof():
                self.entries.append(Nds.OverlayEntry(self._io, self, self._root))
                i += 1



    class ExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.global_mbk1_5_settings = self._io.read_bytes(20)
            self.local_mbk6_8_settings_for_arm9 = self._io.read_bytes(12)
            self.local_mbk6_8_settings_for_arm7 = self._io.read_bytes(12)
            self.global_mdk9_setting = self._io.read_bytes(4)
            self.region_flags = self._io.read_bytes(4)
            self.access_control = self._io.read_bytes(4)
            self.arm7_scrg_ext_mask = self._io.read_bytes(4)
            self.reserved = self._io.read_bytes(4)
            self.arm9i = Nds.CodeSectionInfo(self._io, self, self._root)
            self.arm7i = Nds.CodeSectionInfo(self._io, self, self._root)
            self.digest_ntr_region = Nds.SectionInfo(self._io, self, self._root)
            self.digest_twl_region = Nds.SectionInfo(self._io, self, self._root)
            self.digest_sector_hashtable = Nds.SectionInfo(self._io, self, self._root)
            self.digest_block_hashtable = Nds.SectionInfo(self._io, self, self._root)
            self.digest_section_size = self._io.read_u4le()
            self.digest_block_sectorcount = self._io.read_u4le()
            self.icon_banner_size = self._io.read_u4le()
            self.un1 = self._io.read_u4le()
            self.ntr_twl_region_rom_size = self._io.read_u4le()
            self.un2 = self._io.read_bytes(12)
            self.modcrypt_area_1 = Nds.SectionInfo(self._io, self, self._root)
            self.modcrypt_area_2 = Nds.SectionInfo(self._io, self, self._root)
            self.tital_id = self._io.read_u8le()


    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.game_title = (self._io.read_bytes(12)).decode(u"ascii")
            self.game_code = self._io.read_bytes(4)
            self.maker_code = (self._io.read_bytes(2)).decode(u"ascii")
            self.unit_code = KaitaiStream.resolve_enum(Nds.UnitCodeEnum, self._io.read_u1())
            self.encryption_seed = self._io.read_u1()
            self.device_capacity = self._io.read_u1()
            self.reserved = self._io.read_bytes(7)
            self.game_revision = self._io.read_bytes(2)
            self.rom_version = self._io.read_u1()
            self.internal_flags = self._io.read_u1()
            self.arm9 = Nds.CodeSectionInfo(self._io, self, self._root)
            self.arm7 = Nds.CodeSectionInfo(self._io, self, self._root)
            self.fnt_info = Nds.SectionInfo(self._io, self, self._root)
            self.fat_info = Nds.SectionInfo(self._io, self, self._root)
            self.arm9_overlay = Nds.SectionInfo(self._io, self, self._root)
            self.arm7_overlay = Nds.SectionInfo(self._io, self, self._root)
            self.normal_card_control_register_settings = self._io.read_bytes(4)
            self.secure_card_control_register_settings = self._io.read_bytes(4)
            self.icon_banner_offset = self._io.read_u4le()
            self.secure_area_crc = self._io.read_u2le()
            self.secure_transfer_timeout = self._io.read_u2le()
            self.arm9_autoload = self._io.read_u4le()
            self.arm7_autoload = self._io.read_u4le()
            self.secure_disable = self._io.read_u8le()
            self.ntr_region_rom_size = self._io.read_u4le()
            self.header_size = self._io.read_u4le()
            self.reserved2 = self._io.read_bytes(56)
            self.nintendo_logo = self._io.read_bytes(156)
            self.nintendo_logo_crc = self._io.read_u2le()
            self.header_crc = self._io.read_u2le()
            self.debugger_reserved = self._io.read_bytes(32)


    class File(KaitaiStruct):
        def __init__(self, info, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.info = info
            self._read()

        def _read(self):
            pass

        @property
        def data(self):
            if hasattr(self, '_m_data'):
                return self._m_data

            _pos = self._io.pos()
            self._io.seek(self.info.start_offset)
            self._m_data = self._io.read_bytes((self.info.end_offset - self.info.start_offset))
            self._io.seek(_pos)
            return getattr(self, '_m_data', None)


    class FileEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flag = self._io.read_u1()
            self.name = (self._io.read_bytes(self.name_length)).decode(u"ascii")
            if self.is_directory:
                self.directory_id = self._io.read_u2le()


        @property
        def is_directory(self):
            if hasattr(self, '_m_is_directory'):
                return self._m_is_directory

            self._m_is_directory = (self.flag >> 7)
            return getattr(self, '_m_is_directory', None)

        @property
        def name_length(self):
            if hasattr(self, '_m_name_length'):
                return self._m_name_length

            self._m_name_length = (self.flag & 127)
            return getattr(self, '_m_name_length', None)


    class CodeSectionInfo(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u4le()
            self.entry_address = self._io.read_u4le()
            self.load_address = self._io.read_u4le()
            self.size = self._io.read_u4le()


    class Directory(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.files = []
            i = 0
            while True:
                _ = Nds.FileEntry(self._io, self, self._root)
                self.files.append(_)
                if _.flag == 0:
                    break
                i += 1


    @property
    def file_name_table(self):
        if hasattr(self, '_m_file_name_table'):
            return self._m_file_name_table

        _pos = self._io.pos()
        self._io.seek(self.header.fnt_info.offset)
        self._raw__m_file_name_table = self._io.read_bytes(self.header.fnt_info.size)
        _io__raw__m_file_name_table = KaitaiStream(BytesIO(self._raw__m_file_name_table))
        self._m_file_name_table = Nds.FileNameTable(_io__raw__m_file_name_table, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_file_name_table', None)

    @property
    def file_allocation_table(self):
        if hasattr(self, '_m_file_allocation_table'):
            return self._m_file_allocation_table

        _pos = self._io.pos()
        self._io.seek(self.header.fat_info.offset)
        self._m_file_allocation_table = []
        for i in range(self.header.fat_info.size // 8):
            self._m_file_allocation_table.append(Nds.FatEntry(self._io, self, self._root))

        self._io.seek(_pos)
        return getattr(self, '_m_file_allocation_table', None)

    @property
    def arm9_overlay_table(self):
        if hasattr(self, '_m_arm9_overlay_table'):
            return self._m_arm9_overlay_table

        _pos = self._io.pos()
        self._io.seek(self.header.arm9_overlay.offset)
        self._raw__m_arm9_overlay_table = self._io.read_bytes(self.header.arm9_overlay.size)
        _io__raw__m_arm9_overlay_table = KaitaiStream(BytesIO(self._raw__m_arm9_overlay_table))
        self._m_arm9_overlay_table = Nds.OverlayTable(_io__raw__m_arm9_overlay_table, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_arm9_overlay_table', None)

    @property
    def arm7_overlay_table(self):
        if hasattr(self, '_m_arm7_overlay_table'):
            return self._m_arm7_overlay_table

        _pos = self._io.pos()
        self._io.seek(self.header.arm7_overlay.offset)
        self._raw__m_arm7_overlay_table = self._io.read_bytes(self.header.arm7_overlay.size)
        _io__raw__m_arm7_overlay_table = KaitaiStream(BytesIO(self._raw__m_arm7_overlay_table))
        self._m_arm7_overlay_table = Nds.OverlayTable(_io__raw__m_arm7_overlay_table, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_arm7_overlay_table', None)


