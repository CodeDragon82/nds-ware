package ndsware.nitrosdk.tasks;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import docking.widgets.OptionDialog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ndsware.nitrosdk.NitroSdkProvider;

/**
 * Imports the library binaries from the Nitro SDK ZIP file and disassembles the
 * the functions in each binary.
 */
public class ImportTask extends Task {


    private final File tempDirectory = new File(System.getProperty("java.io.tmpdir"));

    private DomainFolder projectFolder;
    private DomainFolder nitroSdkFolder;
    private File nitroSdkFile;

    public ImportTask(File nitroSdkFile, DomainFolder projectFolder) {
        super("Import Nitro SDK", true, true, true);

        this.nitroSdkFile = nitroSdkFile;
        this.projectFolder = projectFolder;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {

        // Create/load Nitro SDK folder.
        nitroSdkFolder = projectFolder.getFolder(NitroSdkProvider.IMPORTED_NITRO_SDK_FOLDER);
        if (nitroSdkFolder == null) {
            try {
                nitroSdkFolder = projectFolder.createFolder(NitroSdkProvider.IMPORTED_NITRO_SDK_FOLDER);
            } catch (InvalidNameException | IOException e) {
                Msg.showInfo(this, null, "Failed to Create Nitro SDK Folder", e.getMessage());
                return;
            }
        }

        // Parse the Nitro SDK ZIP file.
        ZipFile nitroSdkZip;
        try {
            nitroSdkZip = new ZipFile(nitroSdkFile);
        } catch (IOException e) {
            Msg.showError(this, null, "Failed to Parse ZIP File", e.getMessage());
            return;
        }

        // Parse entries from ZIP file.
        monitor.setMessage("Parsing ZIP file");
        ArrayList<ZipEntry> unixArchives = new ArrayList<ZipEntry>();
        Enumeration<? extends ZipEntry> entries = nitroSdkZip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            if (!entry.isDirectory() && entry.getName().startsWith("NitroSDK/lib") &&
                    entry.getName().endsWith(".a") && entry.getName().contains("Release")) {
                unixArchives.add(entry);
            }
        }

        // If the user doesn't click "Import", end the task.
        String libraryList = unixArchives.stream().map(ZipEntry::getName).reduce((a, b) -> a + "\n" + b).orElse("");
        int result = OptionDialog.showOptionDialog(null, "Import Libraries", libraryList, "Import");
        if (result != OptionDialog.OPTION_ONE) {
            return;
        }

        // Import binary (.o) files, containing in unix archive (.a) files, extracted
        // from the Nitro SDK ZIP.
        monitor.initialize(unixArchives.size());
        for (ZipEntry entry : unixArchives) {
            File unixArchive;
            try {
                unixArchive = extractUnixArchive(nitroSdkZip, entry, monitor);
                importUnixArchive(unixArchive, monitor);
                unixArchive.delete();
            } catch (IOException e) {
                Msg.showError(this, null, "Failed to import " + entry.getName(), e.getMessage());
            }

            monitor.increment();
        }

        monitor.initialize(countBinaries(nitroSdkFolder));
        analyseLibraryBinaries(nitroSdkFolder, monitor);
    }

    /**
     * Extract unix archive (.a) file from ZIP file, and store in temporary
     * directory.
     */
    private File extractUnixArchive(ZipFile zipFile, ZipEntry entry, TaskMonitor monitor)
            throws IOException {
        monitor.setMessage("Extracting " + entry.getName());

        InputStream inputStream = zipFile.getInputStream(entry);
        if (inputStream == null) {
            throw new IOException("ZIP input stream is null!");
        }

        String filename = Paths.get(entry.getName()).getFileName().toString();
        File file = new File(tempDirectory, filename);
        Files.copy(inputStream, file.toPath(), StandardCopyOption.REPLACE_EXISTING);

        return file;
    }

    /**
     * Extract all binary (.o) files from unix archive (.a) file, and import into
     * Ghidra project.
     */
    private void importUnixArchive(File unixArchive, TaskMonitor monitor) throws CancelledException, IOException {
        monitor.setMessage("Importing " + unixArchive.getName());

        FSRL fsrl = FSRL.fromString("file://" + unixArchive.getAbsolutePath());
        BatchInfo batchInfo = new BatchInfo();
        batchInfo.addFile(fsrl, new ConsoleTaskMonitor());

        // ProgramManager set to null so that the imported libraries are NOT opened in
        // Ghidra.
        Task importTask = new ImportUnixArchiveTask(batchInfo, nitroSdkFolder, true, true);
        importTask.run(new ConsoleTaskMonitor());
    }

    private void analyseLibraryBinaries(DomainFolder folder, TaskMonitor monitor) throws CancelledException {
        for (DomainFolder childFolder : folder.getFolders()) {
            analyseLibraryBinaries(childFolder, monitor);
        }

        for (DomainFile childFile : folder.getFiles()) {
            analyseLibraryBinary(childFile, monitor);
            monitor.increment();
        }
    }

    /**
     * Disassembles instructions and updates the address sets for all functions in
     * the given library binary, then saves the changes.
     * 
     * Return false if anything fails.
     */
    private boolean analyseLibraryBinary(DomainFile file, TaskMonitor monitor) {
        monitor.setMessage("Analysing functions in " + file.getName());

        Program libraryProgram;
        try {
            libraryProgram = (Program) file.getDomainObject(new Object(), false, false, monitor);
        } catch (VersionException | CancelledException | IOException e) {
            return false;
        }

        Listing libraryListing = libraryProgram.getListing();
        Disassembler disassembler = Disassembler.getDisassembler(libraryProgram, new ConsoleTaskMonitor(), null);

        int txId = libraryProgram.startTransaction("Analysis");
        for (Function function : libraryProgram.getFunctionManager().getFunctions(true)) {
            try {
                analyseLibraryFunction(function, libraryListing, disassembler);
            } catch (OverlappingFunctionException e) {
                continue;
            }
        }
        libraryProgram.endTransaction(txId, true);

        try {
            libraryProgram.save("Saving " + file.getName(), new ConsoleTaskMonitor());
        } catch (CancelledException | IOException e) {
            return false;
        }

        return true;
    }

    /**
     * Disassembles instructions and updates the address set for a given function
     * within the library binary.
     */
    private void analyseLibraryFunction(Function function, Listing listing, Disassembler disassembler)
            throws OverlappingFunctionException {
        Address startAddress = function.getEntryPoint();

        disassembler.disassemble(startAddress, null);

        // Find function end address.
        Address endAddress = startAddress;
        for (Instruction instruction : listing.getInstructions(startAddress, true)) {
            if (instruction == null) {
                break;
            }

            endAddress = instruction.getAddress();

            if (instruction.getFlowType().isTerminal()) {
                break;
            }
        }

        // Update function address set.
        function.setBody(new AddressSet(startAddress, endAddress));
    }

    private int countBinaries(DomainFolder folder) {
        int count = 0;
        for (DomainFolder childFolder : folder.getFolders()) {
            count += countBinaries(childFolder);
        }

        for (DomainFile file : folder.getFiles()) {
            count += 1;
        }

        return count;
    }

}
