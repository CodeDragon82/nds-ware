// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

package ndsware.parsers;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;

public class Narc extends KaitaiStruct {
    public static Narc fromFile(String fileName) throws IOException {
        return new Narc(new ByteBufferKaitaiStream(fileName));
    }

    public Narc(KaitaiStream _io) {
        this(_io, null, null);
    }

    public Narc(KaitaiStream _io, KaitaiStruct _parent) {
        this(_io, _parent, null);
    }

    public Narc(KaitaiStream _io, KaitaiStruct _parent, Narc _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }
    private void _read() {
        this.header = new GenericHeader(this._io, this, _root);
        this.fileAllocationTable = new Section(this._io, this, _root);
        this.fileNameTable = new Section(this._io, this, _root);
        this.fileSection = new Section(this._io, this, _root);
    }
    public static class DirectoryEntry extends KaitaiStruct {

        public DirectoryEntry(KaitaiStream _io, long directoryId) {
            this(_io, null, null, directoryId);
        }

        public DirectoryEntry(KaitaiStream _io, Narc.DirectoryTable _parent, long directoryId) {
            this(_io, _parent, null, directoryId);
        }

        public DirectoryEntry(KaitaiStream _io, Narc.DirectoryTable _parent, Narc _root, long directoryId) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            this.directoryId = directoryId;
            _read();
        }
        private void _read() {
            this.startOffset = this._io.readU4le();
            this.firstFilePosition = this._io.readU2le();
            this.parentDirectory = this._io.readU2le();
        }
        private long startOffset;
        private int firstFilePosition;
        private int parentDirectory;
        private long directoryId;
        private Narc _root;
        private Narc.DirectoryTable _parent;
        public long startOffset() { return startOffset; }
        public int firstFilePosition() { return firstFilePosition; }
        public int parentDirectory() { return parentDirectory; }
        public long directoryId() { return directoryId; }
        public Narc _root() { return _root; }
        public Narc.DirectoryTable _parent() { return _parent; }
    }
    public static class Section extends KaitaiStruct {
        public static Section fromFile(String fileName) throws IOException {
            return new Section(new ByteBufferKaitaiStream(fileName));
        }

        public Section(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Section(KaitaiStream _io, Narc _parent) {
            this(_io, _parent, null);
        }

        public Section(KaitaiStream _io, Narc _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.magic = new String(this._io.readBytes(4), Charset.forName("ascii"));
            this.size = this._io.readU4le();
            switch (magic()) {
            case "BTAF": {
                this._raw_data = this._io.readBytes((size() - 8));
                KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                this.data = new Btaf(_io__raw_data, this, _root);
                break;
            }
            case "BTNF": {
                this._raw_data = this._io.readBytes((size() - 8));
                KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                this.data = new Btnf(_io__raw_data, this, _root);
                break;
            }
            case "GMIF": {
                this._raw_data = this._io.readBytes((size() - 8));
                KaitaiStream _io__raw_data = new ByteBufferKaitaiStream(_raw_data);
                this.data = new Gmif(_io__raw_data, this, _root);
                break;
            }
            default: {
                this.data = this._io.readBytes((size() - 8));
                break;
            }
            }
        }
        private String magic;
        private long size;
        private Object data;
        private Narc _root;
        private Narc _parent;
        private byte[] _raw_data;
        public String magic() { return magic; }
        public long size() { return size; }
        public Object data() { return data; }
        public Narc _root() { return _root; }
        public Narc _parent() { return _parent; }
        public byte[] _raw_data() { return _raw_data; }
    }
    public static class BtafEntry extends KaitaiStruct {
        public static BtafEntry fromFile(String fileName) throws IOException {
            return new BtafEntry(new ByteBufferKaitaiStream(fileName));
        }

        public BtafEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public BtafEntry(KaitaiStream _io, Narc.Btaf _parent) {
            this(_io, _parent, null);
        }

        public BtafEntry(KaitaiStream _io, Narc.Btaf _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.startOffset = this._io.readU4le();
            this.endOffset = this._io.readU4le();
        }
        private long startOffset;
        private long endOffset;
        private Narc _root;
        private Narc.Btaf _parent;
        public long startOffset() { return startOffset; }
        public long endOffset() { return endOffset; }
        public Narc _root() { return _root; }
        public Narc.Btaf _parent() { return _parent; }
    }
    public static class Gmif extends KaitaiStruct {
        public static Gmif fromFile(String fileName) throws IOException {
            return new Gmif(new ByteBufferKaitaiStream(fileName));
        }

        public Gmif(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Gmif(KaitaiStream _io, Narc.Section _parent) {
            this(_io, _parent, null);
        }

        public Gmif(KaitaiStream _io, Narc.Section _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.files = new ArrayList<File>();
            for (int i = 0; i < fat().fileCount(); i++) {
                this.files.add(new File(this._io, this, _root, fat().entries().get((int) i)));
            }
        }
        private Narc.Btaf fat;
        public Narc.Btaf fat() {
            if (this.fat != null)
                return this.fat;
            this.fat = ((Narc.Btaf) (_root().fileAllocationTable().data()));
            return this.fat;
        }
        private ArrayList<File> files;
        private Narc _root;
        private Narc.Section _parent;
        public ArrayList<File> files() { return files; }
        public Narc _root() { return _root; }
        public Narc.Section _parent() { return _parent; }
    }
    public static class RootEntry extends KaitaiStruct {
        public static RootEntry fromFile(String fileName) throws IOException {
            return new RootEntry(new ByteBufferKaitaiStream(fileName));
        }

        public RootEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public RootEntry(KaitaiStream _io, Narc.DirectoryTable _parent) {
            this(_io, _parent, null);
        }

        public RootEntry(KaitaiStream _io, Narc.DirectoryTable _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.startOffset = this._io.readU4le();
            this.firstFilePosition = this._io.readU2le();
            this.directoryCount = this._io.readU2le();
        }
        private long startOffset;
        private int firstFilePosition;
        private int directoryCount;
        private Narc _root;
        private Narc.DirectoryTable _parent;
        public long startOffset() { return startOffset; }
        public int firstFilePosition() { return firstFilePosition; }
        public int directoryCount() { return directoryCount; }
        public Narc _root() { return _root; }
        public Narc.DirectoryTable _parent() { return _parent; }
    }
    public static class GenericHeader extends KaitaiStruct {
        public static GenericHeader fromFile(String fileName) throws IOException {
            return new GenericHeader(new ByteBufferKaitaiStream(fileName));
        }

        public GenericHeader(KaitaiStream _io) {
            this(_io, null, null);
        }

        public GenericHeader(KaitaiStream _io, Narc _parent) {
            this(_io, _parent, null);
        }

        public GenericHeader(KaitaiStream _io, Narc _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.magic = this._io.readBytes(4);
            if (!(Arrays.equals(magic(), new byte[] { 78, 65, 82, 67 }))) {
                throw new KaitaiStream.ValidationNotEqualError(new byte[] { 78, 65, 82, 67 }, magic(), _io(), "/types/generic_header/seq/0");
            }
            this.blob = this._io.readU4le();
            this.sectionSize = this._io.readU4le();
            this.headerSize = this._io.readU2le();
            this.sectionCount = this._io.readU2le();
        }
        private byte[] magic;
        private long blob;
        private long sectionSize;
        private int headerSize;
        private int sectionCount;
        private Narc _root;
        private Narc _parent;
        public byte[] magic() { return magic; }
        public long blob() { return blob; }
        public long sectionSize() { return sectionSize; }
        public int headerSize() { return headerSize; }
        public int sectionCount() { return sectionCount; }
        public Narc _root() { return _root; }
        public Narc _parent() { return _parent; }
    }
    public static class File extends KaitaiStruct {

        public File(KaitaiStream _io, BtafEntry info) {
            this(_io, null, null, info);
        }

        public File(KaitaiStream _io, Narc.Gmif _parent, BtafEntry info) {
            this(_io, _parent, null, info);
        }

        public File(KaitaiStream _io, Narc.Gmif _parent, Narc _root, BtafEntry info) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            this.info = info;
            _read();
        }
        private void _read() {
        }
        private byte[] data;
        public byte[] data() {
            if (this.data != null)
                return this.data;
            long _pos = this._io.pos();
            this._io.seek((_io().pos() + info().startOffset()));
            this.data = this._io.readBytes((info().endOffset() - info().startOffset()));
            this._io.seek(_pos);
            return this.data;
        }
        private BtafEntry info;
        private Narc _root;
        private Narc.Gmif _parent;
        public BtafEntry info() { return info; }
        public Narc _root() { return _root; }
        public Narc.Gmif _parent() { return _parent; }
    }
    public static class Btnf extends KaitaiStruct {
        public static Btnf fromFile(String fileName) throws IOException {
            return new Btnf(new ByteBufferKaitaiStream(fileName));
        }

        public Btnf(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Btnf(KaitaiStream _io, Narc.Section _parent) {
            this(_io, _parent, null);
        }

        public Btnf(KaitaiStream _io, Narc.Section _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.directoryTable = new DirectoryTable(this._io, this, _root);
            if (_parent().size() > 16) {
                this.directories = new ArrayList<Directory>();
                for (int i = 0; i < directoryTable().count(); i++) {
                    this.directories.add(new Directory(this._io, this, _root));
                }
            }
        }
        private DirectoryTable directoryTable;
        private ArrayList<Directory> directories;
        private Narc _root;
        private Narc.Section _parent;
        public DirectoryTable directoryTable() { return directoryTable; }
        public ArrayList<Directory> directories() { return directories; }
        public Narc _root() { return _root; }
        public Narc.Section _parent() { return _parent; }
    }
    public static class DirectoryContent extends KaitaiStruct {
        public static DirectoryContent fromFile(String fileName) throws IOException {
            return new DirectoryContent(new ByteBufferKaitaiStream(fileName));
        }

        public DirectoryContent(KaitaiStream _io) {
            this(_io, null, null);
        }

        public DirectoryContent(KaitaiStream _io, Narc.Directory _parent) {
            this(_io, _parent, null);
        }

        public DirectoryContent(KaitaiStream _io, Narc.Directory _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.files = new ArrayList<FileEntry>();
            {
                int i = 0;
                while (!this._io.isEof()) {
                    this.files.add(new FileEntry(this._io, this, _root));
                    i++;
                }
            }
        }
        private ArrayList<FileEntry> files;
        private Narc _root;
        private Narc.Directory _parent;
        public ArrayList<FileEntry> files() { return files; }
        public Narc _root() { return _root; }
        public Narc.Directory _parent() { return _parent; }
    }
    public static class DirectoryTable extends KaitaiStruct {
        public static DirectoryTable fromFile(String fileName) throws IOException {
            return new DirectoryTable(new ByteBufferKaitaiStream(fileName));
        }

        public DirectoryTable(KaitaiStream _io) {
            this(_io, null, null);
        }

        public DirectoryTable(KaitaiStream _io, Narc.Btnf _parent) {
            this(_io, _parent, null);
        }

        public DirectoryTable(KaitaiStream _io, Narc.Btnf _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.root = new RootEntry(this._io, this, _root);
            this.directories = new ArrayList<DirectoryEntry>();
            for (int i = 0; i < (root().directoryCount() - 1); i++) {
                this.directories.add(new DirectoryEntry(this._io, this, _root, ((i + 1) | 61440)));
            }
        }
        private Integer count;
        public Integer count() {
            if (this.count != null)
                return this.count;
            int _tmp = (int) (root().directoryCount());
            this.count = _tmp;
            return this.count;
        }
        private RootEntry root;
        private ArrayList<DirectoryEntry> directories;
        private Narc _root;
        private Narc.Btnf _parent;
        public RootEntry root() { return root; }
        public ArrayList<DirectoryEntry> directories() { return directories; }
        public Narc _root() { return _root; }
        public Narc.Btnf _parent() { return _parent; }
    }
    public static class FileEntry extends KaitaiStruct {
        public static FileEntry fromFile(String fileName) throws IOException {
            return new FileEntry(new ByteBufferKaitaiStream(fileName));
        }

        public FileEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FileEntry(KaitaiStream _io, Narc.DirectoryContent _parent) {
            this(_io, _parent, null);
        }

        public FileEntry(KaitaiStream _io, Narc.DirectoryContent _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.flag = new FileFlag(this._io, this, _root);
            this.name = new String(this._io.readBytes(flag().nameLength()), Charset.forName("ascii"));
            if (flag().isDirectory()) {
                this.directoryId = this._io.readU2le();
            }
        }
        private FileFlag flag;
        private String name;
        private Integer directoryId;
        private Narc _root;
        private Narc.DirectoryContent _parent;
        public FileFlag flag() { return flag; }
        public String name() { return name; }
        public Integer directoryId() { return directoryId; }
        public Narc _root() { return _root; }
        public Narc.DirectoryContent _parent() { return _parent; }
    }
    public static class Btaf extends KaitaiStruct {
        public static Btaf fromFile(String fileName) throws IOException {
            return new Btaf(new ByteBufferKaitaiStream(fileName));
        }

        public Btaf(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Btaf(KaitaiStream _io, Narc.Section _parent) {
            this(_io, _parent, null);
        }

        public Btaf(KaitaiStream _io, Narc.Section _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.fileCount = this._io.readU4le();
            this.entries = new ArrayList<BtafEntry>();
            for (int i = 0; i < fileCount(); i++) {
                this.entries.add(new BtafEntry(this._io, this, _root));
            }
        }
        private long fileCount;
        private ArrayList<BtafEntry> entries;
        private Narc _root;
        private Narc.Section _parent;
        public long fileCount() { return fileCount; }
        public ArrayList<BtafEntry> entries() { return entries; }
        public Narc _root() { return _root; }
        public Narc.Section _parent() { return _parent; }
    }
    public static class FileFlag extends KaitaiStruct {
        public static FileFlag fromFile(String fileName) throws IOException {
            return new FileFlag(new ByteBufferKaitaiStream(fileName));
        }

        public FileFlag(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FileFlag(KaitaiStream _io, Narc.FileEntry _parent) {
            this(_io, _parent, null);
        }

        public FileFlag(KaitaiStream _io, Narc.FileEntry _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.isDirectory = this._io.readBitsIntBe(1) != 0;
            this.nameLength = this._io.readBitsIntBe(7);
        }
        private boolean isDirectory;
        private long nameLength;
        private Narc _root;
        private Narc.FileEntry _parent;
        public boolean isDirectory() { return isDirectory; }
        public long nameLength() { return nameLength; }
        public Narc _root() { return _root; }
        public Narc.FileEntry _parent() { return _parent; }
    }
    public static class Directory extends KaitaiStruct {
        public static Directory fromFile(String fileName) throws IOException {
            return new Directory(new ByteBufferKaitaiStream(fileName));
        }

        public Directory(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Directory(KaitaiStream _io, Narc.Btnf _parent) {
            this(_io, _parent, null);
        }

        public Directory(KaitaiStream _io, Narc.Btnf _parent, Narc _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this._raw_content = this._io.readBytesTerm((byte) 0, false, true, true);
            KaitaiStream _io__raw_content = new ByteBufferKaitaiStream(_raw_content);
            this.content = new DirectoryContent(_io__raw_content, this, _root);
        }
        private DirectoryContent content;
        private Narc _root;
        private Narc.Btnf _parent;
        private byte[] _raw_content;
        public DirectoryContent content() { return content; }
        public Narc _root() { return _root; }
        public Narc.Btnf _parent() { return _parent; }
        public byte[] _raw_content() { return _raw_content; }
    }
    private GenericHeader header;
    private Section fileAllocationTable;
    private Section fileNameTable;
    private Section fileSection;
    private Narc _root;
    private KaitaiStruct _parent;
    public GenericHeader header() { return header; }
    public Section fileAllocationTable() { return fileAllocationTable; }
    public Section fileNameTable() { return fileNameTable; }
    public Section fileSection() { return fileSection; }
    public Narc _root() { return _root; }
    public KaitaiStruct _parent() { return _parent; }
}
