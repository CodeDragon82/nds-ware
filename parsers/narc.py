# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Narc(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = Narc.GenericHeader(self._io, self, self._root)
        self.file_allocation_table = Narc.Btaf(self._io, self, self._root)
        self.file_name_table = Narc.Btnf(self._io, self, self._root)
        self.file_section = Narc.Gmif(self._io, self, self._root)

    class DirectoryEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.directory_start_offset = self._io.read_u4le()
            self.first_file_position = self._io.read_u2le()
            self.parent_directory = self._io.read_u2le()


    class BtafEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.start_offset = self._io.read_u4le()
            self.end_offset = self._io.read_u4le()


    class Gmif(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x47\x4D\x49\x46":
                raise kaitaistruct.ValidationNotEqualError(b"\x47\x4D\x49\x46", self.magic, self._io, u"/types/gmif/seq/0")
            self.section_size = self._io.read_u4le()
            self.files = []
            for i in range(self._root.file_allocation_table.file_count):
                self.files.append(Narc.File(self._root.file_allocation_table.entries[i], self._io, self, self._root))



    class GenericHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x4E\x41\x52\x43":
                raise kaitaistruct.ValidationNotEqualError(b"\x4E\x41\x52\x43", self.magic, self._io, u"/types/generic_header/seq/0")
            self.blob = self._io.read_u4le()
            self.section_size = self._io.read_u4le()
            self.header_size = self._io.read_u2le()
            self.section_count = self._io.read_u2le()


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
            self._io.seek((self._io.pos() + self.info.start_offset))
            self._m_data = self._io.read_bytes((self.info.end_offset - self.info.start_offset))
            self._io.seek(_pos)
            return getattr(self, '_m_data', None)


    class Btnf(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x42\x54\x4E\x46":
                raise kaitaistruct.ValidationNotEqualError(b"\x42\x54\x4E\x46", self.magic, self._io, u"/types/btnf/seq/0")
            self.section_size = self._io.read_u4le()
            self.directory_table = Narc.DirectoryEntry(self._io, self, self._root)


    class Btaf(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x42\x54\x41\x46":
                raise kaitaistruct.ValidationNotEqualError(b"\x42\x54\x41\x46", self.magic, self._io, u"/types/btaf/seq/0")
            self.section_size = self._io.read_u4le()
            self.file_count = self._io.read_u4le()
            self.entries = []
            for i in range(self.file_count):
                self.entries.append(Narc.BtafEntry(self._io, self, self._root))




