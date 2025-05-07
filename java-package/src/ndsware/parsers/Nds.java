// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

package ndsware.parsers;

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.nio.charset.Charset;

public class Nds extends KaitaiStruct {
    public static Nds fromFile(String fileName) throws IOException {
        return new Nds(new ByteBufferKaitaiStream(fileName));
    }

    public enum UnitCodeEnum {
        NDS(0),
        NDS_DSI(2),
        DSI(3);

        private final long id;
        UnitCodeEnum(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, UnitCodeEnum> byId = new HashMap<Long, UnitCodeEnum>(3);
        static {
            for (UnitCodeEnum e : UnitCodeEnum.values())
                byId.put(e.id(), e);
        }
        public static UnitCodeEnum byId(long id) { return byId.get(id); }
    }

    public Nds(KaitaiStream _io) {
        this(_io, null, null);
    }

    public Nds(KaitaiStream _io, KaitaiStruct _parent) {
        this(_io, _parent, null);
    }

    public Nds(KaitaiStream _io, KaitaiStruct _parent, Nds _root) {
        super(_io);
        this._parent = _parent;
        this._root = _root == null ? this : _root;
        _read();
    }
    private void _read() {
        this.header = new Header(this._io, this, _root);
        if (header().unitCode() != UnitCodeEnum.NDS) {
            this.extendedHeader = new ExtendedHeader(this._io, this, _root);
        }
        this.files = new ArrayList<File>();
        for (int i = 0; i < fileAllocationTable().size(); i++) {
            this.files.add(new File(this._io, this, _root, fileAllocationTable().get((int) i)));
        }
        this.arm9 = new CodeSection(this._io, this, _root, header().arm9());
        this.arm7 = new CodeSection(this._io, this, _root, header().arm7());
        if (header().unitCode() != UnitCodeEnum.NDS) {
            this.arm9i = new CodeSection(this._io, this, _root, extendedHeader().arm9i());
        }
        if (header().unitCode() != UnitCodeEnum.NDS) {
            this.arm7i = new CodeSection(this._io, this, _root, extendedHeader().arm7i());
        }
        this.arm9Overlays = new ArrayList<Overlay>();
        for (int i = 0; i < arm9OverlayTable().entries().size(); i++) {
            this.arm9Overlays.add(new Overlay(this._io, this, _root, arm9OverlayTable().entries().get((int) i)));
        }
        this.arm7Overlays = new ArrayList<Overlay>();
        for (int i = 0; i < arm7OverlayTable().entries().size(); i++) {
            this.arm7Overlays.add(new Overlay(this._io, this, _root, arm7OverlayTable().entries().get((int) i)));
        }
    }
    public static class CodeSection extends KaitaiStruct {

        public CodeSection(KaitaiStream _io, CodeSectionInfo info) {
            this(_io, null, null, info);
        }

        public CodeSection(KaitaiStream _io, Nds _parent, CodeSectionInfo info) {
            this(_io, _parent, null, info);
        }

        public CodeSection(KaitaiStream _io, Nds _parent, Nds _root, CodeSectionInfo info) {
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
            this._io.seek(info().offset());
            this.data = this._io.readBytes(info().size());
            this._io.seek(_pos);
            return this.data;
        }
        private CodeSectionInfo info;
        private Nds _root;
        private Nds _parent;
        public CodeSectionInfo info() { return info; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class FileNameTable extends KaitaiStruct {
        public static FileNameTable fromFile(String fileName) throws IOException {
            return new FileNameTable(new ByteBufferKaitaiStream(fileName));
        }

        public FileNameTable(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FileNameTable(KaitaiStream _io, Nds _parent) {
            this(_io, _parent, null);
        }

        public FileNameTable(KaitaiStream _io, Nds _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.magic = this._io.readU4le();
            this.sectionSize = this._io.readU2le();
            this.directoryCount = this._io.readU2le();
            this.directoryTable = new ArrayList<DirectoryEntry>();
            for (int i = 0; i < (directoryCount() - 1); i++) {
                this.directoryTable.add(new DirectoryEntry(this._io, this, _root, (i + 1)));
            }
            this.directories = new ArrayList<Directory>();
            for (int i = 0; i < directoryCount(); i++) {
                this.directories.add(new Directory(this._io, this, _root));
            }
        }
        private long magic;
        private int sectionSize;
        private int directoryCount;
        private ArrayList<DirectoryEntry> directoryTable;
        private ArrayList<Directory> directories;
        private Nds _root;
        private Nds _parent;
        public long magic() { return magic; }
        public int sectionSize() { return sectionSize; }
        public int directoryCount() { return directoryCount; }
        public ArrayList<DirectoryEntry> directoryTable() { return directoryTable; }
        public ArrayList<Directory> directories() { return directories; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class OverlayEntry extends KaitaiStruct {
        public static OverlayEntry fromFile(String fileName) throws IOException {
            return new OverlayEntry(new ByteBufferKaitaiStream(fileName));
        }

        public OverlayEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public OverlayEntry(KaitaiStream _io, Nds.OverlayTable _parent) {
            this(_io, _parent, null);
        }

        public OverlayEntry(KaitaiStream _io, Nds.OverlayTable _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.index = this._io.readU4le();
            this.baseAddress = this._io.readU4le();
            this.length = this._io.readU4le();
            this.bssSize = this._io.readU4le();
            this.startAddress = this._io.readU4le();
            this.endAddress = this._io.readU4le();
            this.fileId = this._io.readU4le();
            this.reserved = this._io.readU4le();
        }
        private long index;
        private long baseAddress;
        private long length;
        private long bssSize;
        private long startAddress;
        private long endAddress;
        private long fileId;
        private long reserved;
        private Nds _root;
        private Nds.OverlayTable _parent;
        public long index() { return index; }
        public long baseAddress() { return baseAddress; }
        public long length() { return length; }
        public long bssSize() { return bssSize; }
        public long startAddress() { return startAddress; }
        public long endAddress() { return endAddress; }
        public long fileId() { return fileId; }
        public long reserved() { return reserved; }
        public Nds _root() { return _root; }
        public Nds.OverlayTable _parent() { return _parent; }
    }
    public static class Overlay extends KaitaiStruct {

        public Overlay(KaitaiStream _io, OverlayEntry info) {
            this(_io, null, null, info);
        }

        public Overlay(KaitaiStream _io, Nds _parent, OverlayEntry info) {
            this(_io, _parent, null, info);
        }

        public Overlay(KaitaiStream _io, Nds _parent, Nds _root, OverlayEntry info) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            this.info = info;
            _read();
        }
        private void _read() {
        }
        private File file;
        public File file() {
            if (this.file != null)
                return this.file;
            this.file = _root().files().get((int) info().index());
            return this.file;
        }
        private OverlayEntry info;
        private Nds _root;
        private Nds _parent;
        public OverlayEntry info() { return info; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class DirectoryEntry extends KaitaiStruct {

        public DirectoryEntry(KaitaiStream _io, long id) {
            this(_io, null, null, id);
        }

        public DirectoryEntry(KaitaiStream _io, Nds.FileNameTable _parent, long id) {
            this(_io, _parent, null, id);
        }

        public DirectoryEntry(KaitaiStream _io, Nds.FileNameTable _parent, Nds _root, long id) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            this.id = id;
            _read();
        }
        private void _read() {
            this.directoryOffset = this._io.readU4le();
            this.firstFilePosition = this._io.readU2le();
            this.parentDirectory = this._io.readU2le();
        }
        private long directoryOffset;
        private int firstFilePosition;
        private int parentDirectory;
        private long id;
        private Nds _root;
        private Nds.FileNameTable _parent;
        public long directoryOffset() { return directoryOffset; }
        public int firstFilePosition() { return firstFilePosition; }
        public int parentDirectory() { return parentDirectory; }
        public long id() { return id; }
        public Nds _root() { return _root; }
        public Nds.FileNameTable _parent() { return _parent; }
    }
    public static class SectionInfo extends KaitaiStruct {
        public static SectionInfo fromFile(String fileName) throws IOException {
            return new SectionInfo(new ByteBufferKaitaiStream(fileName));
        }

        public SectionInfo(KaitaiStream _io) {
            this(_io, null, null);
        }

        public SectionInfo(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public SectionInfo(KaitaiStream _io, KaitaiStruct _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.offset = this._io.readU4le();
            this.size = this._io.readU4le();
        }
        private long offset;
        private long size;
        private Nds _root;
        private KaitaiStruct _parent;
        public long offset() { return offset; }
        public long size() { return size; }
        public Nds _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
    }
    public static class FatEntry extends KaitaiStruct {
        public static FatEntry fromFile(String fileName) throws IOException {
            return new FatEntry(new ByteBufferKaitaiStream(fileName));
        }

        public FatEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FatEntry(KaitaiStream _io, Nds _parent) {
            this(_io, _parent, null);
        }

        public FatEntry(KaitaiStream _io, Nds _parent, Nds _root) {
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
        private Nds _root;
        private Nds _parent;
        public long startOffset() { return startOffset; }
        public long endOffset() { return endOffset; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class OverlayTable extends KaitaiStruct {
        public static OverlayTable fromFile(String fileName) throws IOException {
            return new OverlayTable(new ByteBufferKaitaiStream(fileName));
        }

        public OverlayTable(KaitaiStream _io) {
            this(_io, null, null);
        }

        public OverlayTable(KaitaiStream _io, Nds _parent) {
            this(_io, _parent, null);
        }

        public OverlayTable(KaitaiStream _io, Nds _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.entries = new ArrayList<OverlayEntry>();
            {
                int i = 0;
                while (!this._io.isEof()) {
                    this.entries.add(new OverlayEntry(this._io, this, _root));
                    i++;
                }
            }
        }
        private ArrayList<OverlayEntry> entries;
        private Nds _root;
        private Nds _parent;
        public ArrayList<OverlayEntry> entries() { return entries; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class ExtendedHeader extends KaitaiStruct {
        public static ExtendedHeader fromFile(String fileName) throws IOException {
            return new ExtendedHeader(new ByteBufferKaitaiStream(fileName));
        }

        public ExtendedHeader(KaitaiStream _io) {
            this(_io, null, null);
        }

        public ExtendedHeader(KaitaiStream _io, Nds _parent) {
            this(_io, _parent, null);
        }

        public ExtendedHeader(KaitaiStream _io, Nds _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.globalMbk15Settings = this._io.readBytes(20);
            this.localMbk68SettingsForArm9 = this._io.readBytes(12);
            this.localMbk68SettingsForArm7 = this._io.readBytes(12);
            this.globalMdk9Setting = this._io.readBytes(4);
            this.regionFlags = this._io.readBytes(4);
            this.accessControl = this._io.readBytes(4);
            this.arm7ScrgExtMask = this._io.readBytes(4);
            this.reserved = this._io.readBytes(4);
            this.arm9i = new CodeSectionInfo(this._io, this, _root);
            this.arm7i = new CodeSectionInfo(this._io, this, _root);
            this.digestNtrRegion = new SectionInfo(this._io, this, _root);
            this.digestTwlRegion = new SectionInfo(this._io, this, _root);
            this.digestSectorHashtable = new SectionInfo(this._io, this, _root);
            this.digestBlockHashtable = new SectionInfo(this._io, this, _root);
            this.digestSectionSize = this._io.readU4le();
            this.digestBlockSectorcount = this._io.readU4le();
            this.iconBannerSize = this._io.readU4le();
            this.un1 = this._io.readU4le();
            this.ntrTwlRegionRomSize = this._io.readU4le();
            this.un2 = this._io.readBytes(12);
            this.modcryptArea1 = new SectionInfo(this._io, this, _root);
            this.modcryptArea2 = new SectionInfo(this._io, this, _root);
            this.titalId = this._io.readU8le();
        }
        private byte[] globalMbk15Settings;
        private byte[] localMbk68SettingsForArm9;
        private byte[] localMbk68SettingsForArm7;
        private byte[] globalMdk9Setting;
        private byte[] regionFlags;
        private byte[] accessControl;
        private byte[] arm7ScrgExtMask;
        private byte[] reserved;
        private CodeSectionInfo arm9i;
        private CodeSectionInfo arm7i;
        private SectionInfo digestNtrRegion;
        private SectionInfo digestTwlRegion;
        private SectionInfo digestSectorHashtable;
        private SectionInfo digestBlockHashtable;
        private long digestSectionSize;
        private long digestBlockSectorcount;
        private long iconBannerSize;
        private long un1;
        private long ntrTwlRegionRomSize;
        private byte[] un2;
        private SectionInfo modcryptArea1;
        private SectionInfo modcryptArea2;
        private long titalId;
        private Nds _root;
        private Nds _parent;
        public byte[] globalMbk15Settings() { return globalMbk15Settings; }
        public byte[] localMbk68SettingsForArm9() { return localMbk68SettingsForArm9; }
        public byte[] localMbk68SettingsForArm7() { return localMbk68SettingsForArm7; }
        public byte[] globalMdk9Setting() { return globalMdk9Setting; }
        public byte[] regionFlags() { return regionFlags; }
        public byte[] accessControl() { return accessControl; }
        public byte[] arm7ScrgExtMask() { return arm7ScrgExtMask; }
        public byte[] reserved() { return reserved; }
        public CodeSectionInfo arm9i() { return arm9i; }
        public CodeSectionInfo arm7i() { return arm7i; }
        public SectionInfo digestNtrRegion() { return digestNtrRegion; }
        public SectionInfo digestTwlRegion() { return digestTwlRegion; }
        public SectionInfo digestSectorHashtable() { return digestSectorHashtable; }
        public SectionInfo digestBlockHashtable() { return digestBlockHashtable; }
        public long digestSectionSize() { return digestSectionSize; }
        public long digestBlockSectorcount() { return digestBlockSectorcount; }
        public long iconBannerSize() { return iconBannerSize; }
        public long un1() { return un1; }
        public long ntrTwlRegionRomSize() { return ntrTwlRegionRomSize; }
        public byte[] un2() { return un2; }
        public SectionInfo modcryptArea1() { return modcryptArea1; }
        public SectionInfo modcryptArea2() { return modcryptArea2; }
        public long titalId() { return titalId; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class Header extends KaitaiStruct {
        public static Header fromFile(String fileName) throws IOException {
            return new Header(new ByteBufferKaitaiStream(fileName));
        }

        public Header(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Header(KaitaiStream _io, Nds _parent) {
            this(_io, _parent, null);
        }

        public Header(KaitaiStream _io, Nds _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.gameTitle = new String(this._io.readBytes(12), Charset.forName("ascii"));
            this.gameCode = this._io.readBytes(4);
            this.makerCode = new String(this._io.readBytes(2), Charset.forName("ascii"));
            this.unitCode = Nds.UnitCodeEnum.byId(this._io.readU1());
            this.encryptionSeed = this._io.readU1();
            this.deviceCapacity = this._io.readU1();
            this.reserved = this._io.readBytes(7);
            this.gameRevision = this._io.readBytes(2);
            this.romVersion = this._io.readU1();
            this.internalFlags = this._io.readU1();
            this.arm9 = new CodeSectionInfo(this._io, this, _root);
            this.arm7 = new CodeSectionInfo(this._io, this, _root);
            this.fntInfo = new SectionInfo(this._io, this, _root);
            this.fatInfo = new SectionInfo(this._io, this, _root);
            this.arm9Overlay = new SectionInfo(this._io, this, _root);
            this.arm7Overlay = new SectionInfo(this._io, this, _root);
            this.normalCardControlRegisterSettings = this._io.readBytes(4);
            this.secureCardControlRegisterSettings = this._io.readBytes(4);
            this.iconBannerOffset = this._io.readU4le();
            this.secureAreaCrc = this._io.readU2le();
            this.secureTransferTimeout = this._io.readU2le();
            this.arm9Autoload = this._io.readU4le();
            this.arm7Autoload = this._io.readU4le();
            this.secureDisable = this._io.readU8le();
            this.ntrRegionRomSize = this._io.readU4le();
            this.headerSize = this._io.readU4le();
            this.reserved2 = this._io.readBytes(56);
            this.nintendoLogo = this._io.readBytes(156);
            this.nintendoLogoCrc = this._io.readU2le();
            this.headerCrc = this._io.readU2le();
            this.debuggerReserved = this._io.readBytes(32);
        }
        private String gameTitle;
        private byte[] gameCode;
        private String makerCode;
        private UnitCodeEnum unitCode;
        private int encryptionSeed;
        private int deviceCapacity;
        private byte[] reserved;
        private byte[] gameRevision;
        private int romVersion;
        private int internalFlags;
        private CodeSectionInfo arm9;
        private CodeSectionInfo arm7;
        private SectionInfo fntInfo;
        private SectionInfo fatInfo;
        private SectionInfo arm9Overlay;
        private SectionInfo arm7Overlay;
        private byte[] normalCardControlRegisterSettings;
        private byte[] secureCardControlRegisterSettings;
        private long iconBannerOffset;
        private int secureAreaCrc;
        private int secureTransferTimeout;
        private long arm9Autoload;
        private long arm7Autoload;
        private long secureDisable;
        private long ntrRegionRomSize;
        private long headerSize;
        private byte[] reserved2;
        private byte[] nintendoLogo;
        private int nintendoLogoCrc;
        private int headerCrc;
        private byte[] debuggerReserved;
        private Nds _root;
        private Nds _parent;
        public String gameTitle() { return gameTitle; }
        public byte[] gameCode() { return gameCode; }
        public String makerCode() { return makerCode; }
        public UnitCodeEnum unitCode() { return unitCode; }
        public int encryptionSeed() { return encryptionSeed; }
        public int deviceCapacity() { return deviceCapacity; }
        public byte[] reserved() { return reserved; }
        public byte[] gameRevision() { return gameRevision; }
        public int romVersion() { return romVersion; }
        public int internalFlags() { return internalFlags; }
        public CodeSectionInfo arm9() { return arm9; }
        public CodeSectionInfo arm7() { return arm7; }
        public SectionInfo fntInfo() { return fntInfo; }
        public SectionInfo fatInfo() { return fatInfo; }
        public SectionInfo arm9Overlay() { return arm9Overlay; }
        public SectionInfo arm7Overlay() { return arm7Overlay; }
        public byte[] normalCardControlRegisterSettings() { return normalCardControlRegisterSettings; }
        public byte[] secureCardControlRegisterSettings() { return secureCardControlRegisterSettings; }
        public long iconBannerOffset() { return iconBannerOffset; }
        public int secureAreaCrc() { return secureAreaCrc; }
        public int secureTransferTimeout() { return secureTransferTimeout; }
        public long arm9Autoload() { return arm9Autoload; }
        public long arm7Autoload() { return arm7Autoload; }
        public long secureDisable() { return secureDisable; }
        public long ntrRegionRomSize() { return ntrRegionRomSize; }
        public long headerSize() { return headerSize; }
        public byte[] reserved2() { return reserved2; }
        public byte[] nintendoLogo() { return nintendoLogo; }
        public int nintendoLogoCrc() { return nintendoLogoCrc; }
        public int headerCrc() { return headerCrc; }
        public byte[] debuggerReserved() { return debuggerReserved; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class File extends KaitaiStruct {

        public File(KaitaiStream _io, FatEntry info) {
            this(_io, null, null, info);
        }

        public File(KaitaiStream _io, Nds _parent, FatEntry info) {
            this(_io, _parent, null, info);
        }

        public File(KaitaiStream _io, Nds _parent, Nds _root, FatEntry info) {
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
            this._io.seek(info().startOffset());
            this.data = this._io.readBytes((info().endOffset() - info().startOffset()));
            this._io.seek(_pos);
            return this.data;
        }
        private FatEntry info;
        private Nds _root;
        private Nds _parent;
        public FatEntry info() { return info; }
        public Nds _root() { return _root; }
        public Nds _parent() { return _parent; }
    }
    public static class FileEntry extends KaitaiStruct {
        public static FileEntry fromFile(String fileName) throws IOException {
            return new FileEntry(new ByteBufferKaitaiStream(fileName));
        }

        public FileEntry(KaitaiStream _io) {
            this(_io, null, null);
        }

        public FileEntry(KaitaiStream _io, Nds.Directory _parent) {
            this(_io, _parent, null);
        }

        public FileEntry(KaitaiStream _io, Nds.Directory _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.flag = this._io.readU1();
            this.name = new String(this._io.readBytes(nameLength()), Charset.forName("ascii"));
            if (isDirectory()) {
                this.directoryId = this._io.readU2le();
            }
        }
        private Boolean isDirectory;
        public Boolean isDirectory() {
            if (this.isDirectory != null)
                return this.isDirectory;
            boolean _tmp = (boolean) ((flag() >> 7) == 1);
            this.isDirectory = _tmp;
            return this.isDirectory;
        }
        private Integer nameLength;
        public Integer nameLength() {
            if (this.nameLength != null)
                return this.nameLength;
            int _tmp = (int) ((flag() & 127));
            this.nameLength = _tmp;
            return this.nameLength;
        }
        private int flag;
        private String name;
        private Integer directoryId;
        private Nds _root;
        private Nds.Directory _parent;
        public int flag() { return flag; }
        public String name() { return name; }
        public Integer directoryId() { return directoryId; }
        public Nds _root() { return _root; }
        public Nds.Directory _parent() { return _parent; }
    }
    public static class CodeSectionInfo extends KaitaiStruct {
        public static CodeSectionInfo fromFile(String fileName) throws IOException {
            return new CodeSectionInfo(new ByteBufferKaitaiStream(fileName));
        }

        public CodeSectionInfo(KaitaiStream _io) {
            this(_io, null, null);
        }

        public CodeSectionInfo(KaitaiStream _io, KaitaiStruct _parent) {
            this(_io, _parent, null);
        }

        public CodeSectionInfo(KaitaiStream _io, KaitaiStruct _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.offset = this._io.readU4le();
            this.entryAddress = this._io.readU4le();
            this.loadAddress = this._io.readU4le();
            this.size = this._io.readU4le();
        }
        private long offset;
        private long entryAddress;
        private long loadAddress;
        private long size;
        private Nds _root;
        private KaitaiStruct _parent;
        public long offset() { return offset; }
        public long entryAddress() { return entryAddress; }
        public long loadAddress() { return loadAddress; }
        public long size() { return size; }
        public Nds _root() { return _root; }
        public KaitaiStruct _parent() { return _parent; }
    }
    public static class Directory extends KaitaiStruct {
        public static Directory fromFile(String fileName) throws IOException {
            return new Directory(new ByteBufferKaitaiStream(fileName));
        }

        public Directory(KaitaiStream _io) {
            this(_io, null, null);
        }

        public Directory(KaitaiStream _io, Nds.FileNameTable _parent) {
            this(_io, _parent, null);
        }

        public Directory(KaitaiStream _io, Nds.FileNameTable _parent, Nds _root) {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _read();
        }
        private void _read() {
            this.files = new ArrayList<FileEntry>();
            {
                FileEntry _it;
                int i = 0;
                do {
                    _it = new FileEntry(this._io, this, _root);
                    this.files.add(_it);
                    i++;
                } while (!(_it.flag() == 0));
            }
        }
        private ArrayList<FileEntry> files;
        private Nds _root;
        private Nds.FileNameTable _parent;
        public ArrayList<FileEntry> files() { return files; }
        public Nds _root() { return _root; }
        public Nds.FileNameTable _parent() { return _parent; }
    }
    private FileNameTable fileNameTable;
    public FileNameTable fileNameTable() {
        if (this.fileNameTable != null)
            return this.fileNameTable;
        long _pos = this._io.pos();
        this._io.seek(header().fntInfo().offset());
        this._raw_fileNameTable = this._io.readBytes(header().fntInfo().size());
        KaitaiStream _io__raw_fileNameTable = new ByteBufferKaitaiStream(_raw_fileNameTable);
        this.fileNameTable = new FileNameTable(_io__raw_fileNameTable, this, _root);
        this._io.seek(_pos);
        return this.fileNameTable;
    }
    private ArrayList<FatEntry> fileAllocationTable;
    public ArrayList<FatEntry> fileAllocationTable() {
        if (this.fileAllocationTable != null)
            return this.fileAllocationTable;
        long _pos = this._io.pos();
        this._io.seek(header().fatInfo().offset());
        this.fileAllocationTable = new ArrayList<FatEntry>();
        for (int i = 0; i < (header().fatInfo().size() / 8); i++) {
            this.fileAllocationTable.add(new FatEntry(this._io, this, _root));
        }
        this._io.seek(_pos);
        return this.fileAllocationTable;
    }
    private OverlayTable arm9OverlayTable;
    public OverlayTable arm9OverlayTable() {
        if (this.arm9OverlayTable != null)
            return this.arm9OverlayTable;
        long _pos = this._io.pos();
        this._io.seek(header().arm9Overlay().offset());
        this._raw_arm9OverlayTable = this._io.readBytes(header().arm9Overlay().size());
        KaitaiStream _io__raw_arm9OverlayTable = new ByteBufferKaitaiStream(_raw_arm9OverlayTable);
        this.arm9OverlayTable = new OverlayTable(_io__raw_arm9OverlayTable, this, _root);
        this._io.seek(_pos);
        return this.arm9OverlayTable;
    }
    private OverlayTable arm7OverlayTable;
    public OverlayTable arm7OverlayTable() {
        if (this.arm7OverlayTable != null)
            return this.arm7OverlayTable;
        long _pos = this._io.pos();
        this._io.seek(header().arm7Overlay().offset());
        this._raw_arm7OverlayTable = this._io.readBytes(header().arm7Overlay().size());
        KaitaiStream _io__raw_arm7OverlayTable = new ByteBufferKaitaiStream(_raw_arm7OverlayTable);
        this.arm7OverlayTable = new OverlayTable(_io__raw_arm7OverlayTable, this, _root);
        this._io.seek(_pos);
        return this.arm7OverlayTable;
    }
    private Header header;
    private ExtendedHeader extendedHeader;
    private ArrayList<File> files;
    private CodeSection arm9;
    private CodeSection arm7;
    private CodeSection arm9i;
    private CodeSection arm7i;
    private ArrayList<Overlay> arm9Overlays;
    private ArrayList<Overlay> arm7Overlays;
    private Nds _root;
    private KaitaiStruct _parent;
    private byte[] _raw_fileNameTable;
    private byte[] _raw_arm9OverlayTable;
    private byte[] _raw_arm7OverlayTable;
    public Header header() { return header; }
    public ExtendedHeader extendedHeader() { return extendedHeader; }
    public ArrayList<File> files() { return files; }
    public CodeSection arm9() { return arm9; }
    public CodeSection arm7() { return arm7; }
    public CodeSection arm9i() { return arm9i; }
    public CodeSection arm7i() { return arm7i; }
    public ArrayList<Overlay> arm9Overlays() { return arm9Overlays; }
    public ArrayList<Overlay> arm7Overlays() { return arm7Overlays; }
    public Nds _root() { return _root; }
    public KaitaiStruct _parent() { return _parent; }
    public byte[] _raw_fileNameTable() { return _raw_fileNameTable; }
    public byte[] _raw_arm9OverlayTable() { return _raw_arm9OverlayTable; }
    public byte[] _raw_arm7OverlayTable() { return _raw_arm7OverlayTable; }
}
