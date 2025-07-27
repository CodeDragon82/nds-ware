package ndsware.nitrosdk.tasks;

import java.io.IOException;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ndsware.nitrosdk.LibraryNode;

/**
 * Loads functions from the Nitro SDK library binaries and stores them in a
 * custom `GTree` in the "Nitro SDK" window. For each function, the name and the
 * byte signature are stored in a `LibraryNode`.
 */
public class LoadTask extends Task {

    private Program program;
    private DomainFolder nitroSdkFolder;
    private LibraryNode libraryRoot;

    public LoadTask(Program program, DomainFolder nitroSdkFolder, LibraryNode libraryRoot) {
        super("Load Nitro SDK");

        this.program = program;
        this.nitroSdkFolder = nitroSdkFolder;
        this.libraryRoot = libraryRoot;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        if (nitroSdkFolder != null) {
            loadLibrary(nitroSdkFolder, libraryRoot, monitor);
        }
    }

    private void loadLibrary(DomainFolder folder, LibraryNode node, TaskMonitor monitor) {
        for (DomainFolder childFolder : folder.getFolders()) {
            LibraryNode childNode = new LibraryNode(childFolder.getName());
            node.addNode(childNode);

            loadLibrary(childFolder, childNode, monitor);
        }

        for (DomainFile childFile : folder.getFiles()) {
            LibraryNode childNode = new LibraryNode(childFile.getName());
            node.addNode(childNode);

            try {
                loadLibrary(childFile, childNode, monitor);
            } catch (VersionException | CancelledException | MemoryAccessException | IOException e) {
                Msg.showError(this, null, "Failed to load " + childFile.getName(), e.getMessage());
            }
        }
    }

    private void loadLibrary(DomainFile file, LibraryNode node, TaskMonitor monitor)
            throws VersionException, CancelledException, IOException, MemoryAccessException {

        monitor.setMessage("Loading " + file.getName());

        Program libraryProgram = (Program) file.getDomainObject(new Object(), false, false, monitor);
        Memory libraryMemory = libraryProgram.getMemory();

        for (Function function : libraryProgram.getFunctionManager().getFunctions(true)) {

            String functionName = function.getName();
            byte[] functionBytes = new byte[(int) function.getBody().getNumAddresses()];
            libraryMemory.getBytes(function.getBody().getMinAddress(), functionBytes);

            // Skip loading library functions that were incorrectly analysed when the Nitro
            // SDK was imported.
            if (functionBytes.length <= 1) {
                continue;
            }

            LibraryNode newNode = new LibraryNode(functionName, functionBytes, program.getSymbolTable());
            node.addNode(newNode);
        }
    }

}
