package ndsware.nitrosdk.tasks;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

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
import ndsware.misc.ExtraInfoDialog;
import ndsware.nitrosdk.NitroSdkProvider;

/**
 * Imports the library binaries from the Nitro SDK ZIP file and disassembles the
 * the functions in each binary.
 */
public class ImportTask extends Task {

    private static final String TASK_NAME = "Import Nitro SDK";
    private static final String DELETE_FOLDER_EEROR = "Failed to Delete Existing Nitro SDK";
    private static final String CREATE_FOLDER_ERROR = "Failed to Create Nitro SDK Folder";
    private static final String PARSE_ZIP_ERROR = "Failed to Parse ZIP File";
    private static final String OVERWRITE_QUESTION = "Nitro SDK has already been imported. Do you want to overwrite it?\n\nWARNING: The previous Nitro SDK import will be deleted.";
    private static final String IMPORT_QUESTION = "Do you want to import the following %d libraries from the Nitro SDK?";

    private final File tempDirectory = new File(System.getProperty("java.io.tmpdir"));
    private final FileNameExtensionFilter ZIP_FILTER = new FileNameExtensionFilter("ZIP files", "zip");

    private DomainFolder projectFolder;
    private DomainFolder nitroSdkFolder;

    private ZipFile nitroSdkZip;
    private List<ZipEntry> nitroSdkZipEntries;

    public ImportTask(DomainFolder projectFolder) {
        super(TASK_NAME, true, true, true);

        this.projectFolder = projectFolder;
    }

    /**
     * Sets up the task by:
     * <ul>
     * <li>Creating/loading the Nitro SDK project folder.
     * <li>Asking the user to select a Nitro SDK ZIP file.
     * <li>Fetch the ZIP entries for the Nitro SDK archive (.a) files.
     * </ul>
     * 
     * Returns true if the task is ready to run.
     */
    public boolean setup() {

        // Let the user select the Nitro SDK ZIP file.
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(ZIP_FILTER);
        if (fileChooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) {
            Msg.showError(this, null, "Invalid File", "Cannot import Nitro SDK from a non-ZIP file.");
            return false;
        }
        File nitroSdkZipFile = fileChooser.getSelectedFile();

        // Parse the Nitro SDK ZIP file.
        try {
            nitroSdkZip = new ZipFile(nitroSdkZipFile);
        } catch (IOException e) {
            Msg.showError(this, null, PARSE_ZIP_ERROR, e.getMessage());
            return false;
        }

        // Filter entries from ZIP file.
        nitroSdkZipEntries = Collections.list(nitroSdkZip.entries()).stream()
                .filter(entry -> !entry.isDirectory())
                .filter(entry -> entry.getName().startsWith("NitroSDK/lib"))
                .filter(entry -> entry.getName().endsWith(".a"))
                .filter(entry -> entry.getName().contains("Release"))
                .collect(Collectors.toList());

        String libraryList = nitroSdkZipEntries.stream()
                .map(entry -> new File(entry.getName()).getName())
                .reduce((a, b) -> a + "\n" + b).orElse("");
        String importQuestion = String.format(IMPORT_QUESTION, nitroSdkZipEntries.size());

        // Ask the user if they want to import the Nitro SDK libraries.
        if (!ExtraInfoDialog.ask(null, "Import Libraries", importQuestion, libraryList, "Import")) {
            return false;
        }

        nitroSdkFolder = projectFolder.getFolder(NitroSdkProvider.IMPORTED_NITRO_SDK_FOLDER);
        if (nitroSdkFolder != null) {

            // If the Nitro SDK folder already exists in project, ask the user if they want
            // to overwrite it.
            if (OptionDialog.showYesNoDialog(null, "Overwrite Existing Nitro SDK",
                    OVERWRITE_QUESTION) != OptionDialog.YES_OPTION) {
                return false;
            }

            // Delete existing Nitro SDK folder.
            try {
                recursiveDelete(nitroSdkFolder);
            } catch (IOException e) {
                Msg.showError(this, null, DELETE_FOLDER_EEROR, e.getMessage());
                return false;
            }
        }

        // Create new Nitro SDK folder.
        try {
            nitroSdkFolder = projectFolder.createFolder(NitroSdkProvider.IMPORTED_NITRO_SDK_FOLDER);
        } catch (InvalidNameException | IOException e) {
            Msg.showError(this, null, CREATE_FOLDER_ERROR, e.getMessage());
            return false;
        }

        return true;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {

        // Import binary (.o) files, containing in unix archive (.a) files, extracted
        // from the Nitro SDK ZIP.
        monitor.initialize(nitroSdkZipEntries.size());
        for (ZipEntry entry : nitroSdkZipEntries) {
            try {
                File unixArchive = extractUnixArchive(nitroSdkZip, entry, monitor);
                importUnixArchive(unixArchive, monitor);
                unixArchive.delete();
                DomainFolder libraryFolder = nitroSdkFolder.getFolder(unixArchive.getName());
                analyseLibrary(libraryFolder, monitor);
            } catch (IOException | VersionException e) {
                Msg.showError(this, null, "Failed to import " + entry.getName(), e.getMessage());
            }

            monitor.increment();
        }
    }

    /**
     * Extract unix archive (.a) file from ZIP file, and store in temporary
     * directory.
     */
    private File extractUnixArchive(ZipFile zipFile, ZipEntry entry, TaskMonitor monitor)
            throws IOException {
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

    private void analyseLibrary(DomainFolder folder, TaskMonitor monitor)
            throws CancelledException, VersionException, IOException {
        monitor.setMessage("Analysing " + folder.getName());

        for (DomainFile childFile : folder.getFiles()) {
            analyseLibraryBinary(childFile, monitor);
        }
    }

    /**
     * Disassembles instructions and updates the address sets for all functions in
     * the given library binary, then saves the changes.
     */
    private void analyseLibraryBinary(DomainFile file, TaskMonitor monitor)
            throws VersionException, CancelledException, IOException {
        Program libraryProgram = (Program) file.getDomainObject(this, false, false, monitor);

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

        libraryProgram.save("Saving " + file.getName(), new ConsoleTaskMonitor());
        libraryProgram.release(this);
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

    private void recursiveDelete(DomainFolder folder) throws IOException {
        for (DomainFolder childFolder : folder.getFolders()) {
            recursiveDelete(childFolder);
        }

        for (DomainFile childFile : folder.getFiles()) {
            childFile.delete();
        }

        folder.delete();
    }

}
