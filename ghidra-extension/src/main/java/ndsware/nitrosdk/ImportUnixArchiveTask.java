package ndsware.nitrosdk;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.FilenameUtils;

import generic.stl.Pair;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectDataUtils;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.plugins.importer.batch.BatchGroup;
import ghidra.plugins.importer.batch.BatchGroupLoadSpec;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ImportUnixArchiveTask extends Task {
    public static final int MAX_PROGRAMS_TO_OPEN = 50;
    private BatchInfo batchInfo;
    private DomainFolder destFolder;
    private boolean stripLeadingPath = true;
    private boolean stripAllContainerPath = false;
    private int totalAppsImported;
    private int totalEnabledApps;

    public ImportUnixArchiveTask(BatchInfo batchInfo, DomainFolder destFolder,
            boolean stripLeading, boolean stripAllContainerPath) {
        super("Batch Import Task", true, true, false, false);
        this.batchInfo = batchInfo;
        this.destFolder = destFolder;
        this.totalEnabledApps = batchInfo.getEnabledCount();
        this.stripLeadingPath = stripLeading;
        this.stripAllContainerPath = stripAllContainerPath;
    }

    public void run(TaskMonitor monitor) {
        try {
            this.doBatchImport(monitor);
        } catch (CancelledException var7) {
            Msg.debug(this, "Batch import cancelled");
        } catch (IOException var8) {
            Msg.error(this, "Error during batch import: ", var8);
        }
    }

    private void doBatchImport(TaskMonitor monitor) throws CancelledException, IOException {
        int var10001 = this.totalEnabledApps;
        Msg.info(this, "Starting batch import of " + var10001 + " programs into " + String.valueOf(this.destFolder));
        Iterator var2 = this.batchInfo.getGroups().iterator();

        while (var2.hasNext()) {
            BatchGroup batchGroup = (BatchGroup) var2.next();
            if (batchGroup.isEnabled()) {
                if (monitor.isCancelled()) {
                    Msg.info(this, "Stopping batch import due to cancel");
                    break;
                }

                this.doImportBatchGroup(batchGroup, monitor);
            }
        }

    }

    private void doImportBatchGroup(BatchGroup batchGroup, TaskMonitor monitor) throws CancelledException, IOException {
        BatchGroupLoadSpec selectedBatchGroupLoadSpec = batchGroup.getSelectedBatchGroupLoadSpec();
        Iterator var4 = batchGroup.getBatchLoadConfig().iterator();

        while (var4.hasNext()) {
            BatchGroup.BatchLoadConfig loadConfig = (BatchGroup.BatchLoadConfig) var4.next();
            if (monitor.isCancelled()) {
                return;
            }

            this.doImportApp(loadConfig, selectedBatchGroupLoadSpec, monitor);
        }

    }

    private void doImportApp(BatchGroup.BatchLoadConfig batchLoadConfig, BatchGroupLoadSpec selectedBatchGroupLoadSpec,
            TaskMonitor monitor) throws CancelledException, IOException {
        Msg.info(this, "Importing " + String.valueOf(batchLoadConfig.getFSRL()));
        ByteProvider byteProvider = FileSystemService.getInstance().getByteProvider(batchLoadConfig.getFSRL(), true,
                monitor);

        label119: {
            try {
                LoadSpec loadSpec = batchLoadConfig.getLoadSpec(selectedBatchGroupLoadSpec);
                if (loadSpec != null) {
                    Pair<DomainFolder, String> destInfo = this.getDestinationInfo(batchLoadConfig, this.destFolder);
                    Object consumer = new Object();

                    try {
                        MessageLog messageLog = new MessageLog();
                        Project project = AppInfo.getActiveProject();
                        LoadResults<? extends DomainObject> loadResults = loadSpec.getLoader().load(byteProvider,
                                this.fixupProjectFilename((String) destInfo.second), project,
                                ((DomainFolder) destInfo.first).getPathname(), loadSpec,
                                this.getOptionsFor(batchLoadConfig, loadSpec, byteProvider), messageLog, consumer,
                                monitor);
                        if (loadResults != null) {
                            try {
                                loadResults.save(project, consumer, messageLog, monitor);
                            } finally {
                                loadResults.release(consumer);
                            }
                        }

                        ++this.totalAppsImported;
                        String var10001 = String.valueOf(destInfo.first);
                        Msg.info(this, "Imported " + var10001 + "/ " + (String) destInfo.second + ", "
                                + this.totalAppsImported + " of " + this.totalEnabledApps);
                        if (!Loader.loggingDisabled && messageLog.hasMessages()) {
                            Msg.info(this, "Additional info:\n" + messageLog.toString());
                        }
                    } catch (CancelledException var19) {
                        Msg.debug(this, "Batch Import cancelled");
                    } catch (VersionException | IllegalArgumentException | IOException var20) {
                        Msg.error(this, "Import failed for " + batchLoadConfig.getPreferredFileName(), var20);
                    }
                    break label119;
                }

                Msg.error(this, "Failed to get load spec from application that matches chosen batch load spec "
                        + String.valueOf(selectedBatchGroupLoadSpec));
            } catch (Throwable var21) {
                if (byteProvider != null) {
                    try {
                        byteProvider.close();
                    } catch (Throwable var17) {
                        var21.addSuppressed(var17);
                    }
                }

                throw var21;
            }

            if (byteProvider != null) {
                byteProvider.close();
            }

            return;
        }

        if (byteProvider != null) {
            byteProvider.close();
        }

    }

    private String fixupProjectFilename(String filename) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < filename.length(); ++i) {
            char ch = filename.charAt(i);
            sb.append(LocalFileSystem.isValidNameCharacter(ch) ? ch : '_');
        }

        return sb.toString();
    }

    static String fsrlToPath(FSRL fsrl, FSRL userSrc, boolean stripLeadingPath, boolean stripInteriorContainerPath) {
        String fullPath = fsrl.toPrettyFullpathString().replace('|', '/');
        String userSrcPath = userSrc.toPrettyFullpathString().replace('|', '/');
        int filename = fullPath.lastIndexOf(47) + 1;
        int uas = userSrcPath.length();
        int container = uas + 1;
        int leadStart = !stripLeadingPath ? 0 : userSrcPath.lastIndexOf(47) + 1;
        int leadEnd = Math.min(filename, userSrcPath.length());
        String leading = leadStart < filename ? fullPath.substring(leadStart, leadEnd) : "";
        String containerPath = container < filename && !stripInteriorContainerPath
                ? fullPath.substring(container, filename)
                : "";
        String filenameStr = fullPath.substring(filename);
        String result = FSUtilities.appendPath(new String[] { leading, containerPath, filenameStr });
        return result;
    }

    private Pair<DomainFolder, String> getDestinationInfo(BatchGroup.BatchLoadConfig batchLoadConfig,
            DomainFolder rootDestinationFolder) {
        FSRL fsrl = batchLoadConfig.getFSRL();
        String pathStr = fsrlToPath(fsrl, batchLoadConfig.getUasi().getFSRL(), this.stripLeadingPath,
                this.stripAllContainerPath);
        String preferredName = batchLoadConfig.getPreferredFileName();
        String fsrlFilename = fsrl.getName();
        if (!fsrlFilename.equals(preferredName)) {
            pathStr = FSUtilities.appendPath(new String[] { pathStr, preferredName });
        }

        pathStr = pathStr.replaceAll("[\\\\:|]+", "/");
        String parentDir = FilenameUtils.getFullPathNoEndSeparator(pathStr);
        if (parentDir == null) {
            parentDir = "";
        }

        String destFilename = FilenameUtils.getName(pathStr);

        try {
            DomainFolder batchDestFolder = ProjectDataUtils.createDomainFolderPath(rootDestinationFolder, parentDir);
            return new Pair(batchDestFolder, destFilename);
        } catch (IOException | InvalidNameException var10) {
            Msg.error(this, "Problem creating project folder root: " + rootDestinationFolder.getPathname()
                    + ", subpath: " + parentDir, var10);
            return new Pair(rootDestinationFolder, fsrlFilename);
        }
    }

    private List<Option> getOptionsFor(BatchGroup.BatchLoadConfig batchLoadConfig, LoadSpec loadSpec,
            ByteProvider byteProvider) {
        List<Option> options = batchLoadConfig.getLoader().getDefaultOptions(byteProvider, loadSpec,
                (DomainObject) null, false);
        return options;
    }
}
