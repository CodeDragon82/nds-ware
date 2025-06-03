# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class G2d(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = G2d.Header(self._io, self, self._root)
        self.blocks = []
        for i in range(self.header.block_count):
            self.blocks.append(G2d.Block(self._io, self, self._root))


    class PlttBlock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.colour_format = self._io.read_u4le()
            self.extended_palette = self._io.read_u4le()
            self.palette_data_size = self._io.read_u4le()
            self.palette_data_offset = self._io.read_u4le()

        @property
        def palette_data(self):
            if hasattr(self, '_m_palette_data'):
                return self._m_palette_data

            _pos = self._io.pos()
            self._io.seek(((self._io.pos() - 16) + self.palette_data_offset))
            self._m_palette_data = self._io.read_bytes(self.palette_data_size)
            self._io.seek(_pos)
            return getattr(self, '_m_palette_data', None)


    class CharBlock(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.width = self._io.read_u2le()
            self.height = self._io.read_u2le()
            self.colour_format = self._io.read_u4le()
            self.mapping_mode = self._io.read_u4le()
            self.graphics_type = self._io.read_u4le()
            self.graphics_data_size = self._io.read_u4le()
            self.graphics_data_offset = self._io.read_u4le()
            self._raw_graphics_data = self._io.read_bytes(self.graphics_data_size)
            _io__raw_graphics_data = KaitaiStream(BytesIO(self._raw_graphics_data))
            self.graphics_data = G2d.GraphicsData(_io__raw_graphics_data, self, self._root)


    class Block(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = (self._io.read_bytes(4)).decode(u"utf-8")
            self.size = self._io.read_u4le()
            _on = self.magic
            if _on == u"TTLP":
                self.data = G2d.PlttBlock(self._io, self, self._root)
            elif _on == u"RAHC":
                self.data = G2d.CharBlock(self._io, self, self._root)


    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = (self._io.read_bytes(4)).decode(u"utf-8")
            self.byte_order = self._io.read_u2le()
            self.version = self._io.read_u2le()
            self.file_size = self._io.read_u4le()
            self.header_size = self._io.read_u2le()
            self.block_count = self._io.read_u2le()


    class GraphicsData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.tiles = []
            i = 0
            while not self._io.is_eof():
                self.tiles.append(self._io.read_bytes(32))
                i += 1




