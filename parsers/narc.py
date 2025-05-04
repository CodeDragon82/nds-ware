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
        self.file_allocation_table = Narc.Section(self._io, self, self._root)
        self.file_name_table = Narc.Section(self._io, self, self._root)
        self.file_section = Narc.Section(self._io, self, self._root)

    class DirectoryEntry(KaitaiStruct):
        def __init__(self, directory_id, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.directory_id = directory_id
            self._read()

        def _read(self):
            self.start_offset = self._io.read_u4le()
            self.first_file_position = self._io.read_u2le()
            self.parent_directory = self._io.read_u2le()


    class Section(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = (self._io.read_bytes(4)).decode(u"ascii")
            self.size = self._io.read_u4le()
            _on = self.magic
            if _on == u"BTAF":
                self._raw_data = self._io.read_bytes((self.size - 8))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = Narc.Btaf(_io__raw_data, self, self._root)
            elif _on == u"BTNF":
                self._raw_data = self._io.read_bytes((self.size - 8))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = Narc.Btnf(_io__raw_data, self, self._root)
            elif _on == u"GMIF":
                self._raw_data = self._io.read_bytes((self.size - 8))
                _io__raw_data = KaitaiStream(BytesIO(self._raw_data))
                self.data = Narc.Gmif(_io__raw_data, self, self._root)
            else:
                self.data = self._io.read_bytes((self.size - 8))


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
            self.files = []
            for i in range(self.fat.file_count):
                self.files.append(Narc.File(self.fat.entries[i], self._io, self, self._root))


        @property
        def fat(self):
            if hasattr(self, '_m_fat'):
                return self._m_fat

            self._m_fat = self._root.file_allocation_table.data
            return getattr(self, '_m_fat', None)


    class RootEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.start_offset = self._io.read_u4le()
            self.first_file_position = self._io.read_u2le()
            self.directory_count = self._io.read_u2le()


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
            self.directory_table = Narc.DirectoryTable(self._io, self, self._root)
            if self._parent.size > 16:
                self.directories = []
                for i in range(self.directory_table.count):
                    self.directories.append(Narc.Directory(self._io, self, self._root))




    class DirectoryContent(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.files = []
            i = 0
            while not self._io.is_eof():
                self.files.append(Narc.FileEntry(self._io, self, self._root))
                i += 1



    class DirectoryTable(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.root = Narc.RootEntry(self._io, self, self._root)
            self.directories = []
            for i in range((self.root.directory_count - 1)):
                self.directories.append(Narc.DirectoryEntry(((i + 1) | 61440), self._io, self, self._root))


        @property
        def count(self):
            if hasattr(self, '_m_count'):
                return self._m_count

            self._m_count = self.root.directory_count
            return getattr(self, '_m_count', None)


    class FileEntry(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flag = Narc.FileFlag(self._io, self, self._root)
            self.name = (self._io.read_bytes(self.flag.name_length)).decode(u"ascii")
            if self.flag.is_directory:
                self.directory_id = self._io.read_u2le()



    class Btaf(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.file_count = self._io.read_u4le()
            self.entries = []
            for i in range(self.file_count):
                self.entries.append(Narc.BtafEntry(self._io, self, self._root))



    class FileFlag(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.is_directory = self._io.read_bits_int_be(1) != 0
            self.name_length = self._io.read_bits_int_be(7)


    class Directory(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self._raw_content = self._io.read_bytes_term(0, False, True, True)
            _io__raw_content = KaitaiStream(BytesIO(self._raw_content))
            self.content = Narc.DirectoryContent(_io__raw_content, self, self._root)



