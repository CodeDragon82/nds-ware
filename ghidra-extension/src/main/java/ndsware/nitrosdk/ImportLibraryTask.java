package ndsware.nitrosdk;

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
import ghidra.framework.model.DomainFolder;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ImportLibraryTask extends Task {

    private final File tempDirectory = new File(System.getProperty("java.io.tmpdir"));

    private DomainFolder projectFolder;
    private DomainFolder nitroSdkFolder;
    private File nitroSdkFile;

    public ImportLibraryTask(File nitroSdkFile, DomainFolder projectFolder) {
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

}
