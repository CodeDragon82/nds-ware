package ndsware.nitrosdk;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class AnalyseLibraryTask extends Task {

    private final Program program;
    private final LibraryNode rootNode;

    public AnalyseLibraryTask(Program program, LibraryNode rootNode) {
        super("Finding and Labelling Nitro SDK Functions", true, true, true);
        this.program = program;
        this.rootNode = rootNode;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        monitor.setMessage("Started analyse for Nitro SDK function...");

        analyseLibrary(rootNode, monitor, "");
    }

    /**
     * Find and label all functions from the given library within the binary.
     */
    private void analyseLibrary(LibraryNode node, TaskMonitor monitor, String path) {

        // Stop searching if the user cancels the task.
        if (monitor.isCancelled()) {
            return;
        }

        path += "/" + node.getFunctionName();

        if (node.isLeaf()) {
            findAndLabelFunction(node, monitor, path);
        } else {
            for (GTreeNode childNode : node.getChildren()) {
                analyseLibrary((LibraryNode) childNode, monitor, path);
            }
        }
    }

    private void findAndLabelFunction(LibraryNode library, TaskMonitor monitor, String path) {
        monitor.setMessage("Analysing " + path + "...");

        Memory memory = program.getMemory();
        SymbolTable symbolTable = program.getSymbolTable();

        Address functionAddress = memory.findBytes(program.getMinAddress(),
                program.getMaxAddress(), library.getFunctionBytes(), null, true,
                monitor);

        if (functionAddress == null) {
            return;
        }

        int transactionID = program.startTransaction("Label " + library.getFunctionName());
        boolean success = false;
        try {
            symbolTable.createLabel(functionAddress, library.getFunctionName(),
                    SourceType.USER_DEFINED);
            success = true;
        } catch (InvalidInputException e) {
            monitor.setMessage("Failed to label " + library.getFunctionName() + ": " + e.getMessage());
        }
        program.endTransaction(transactionID, success);
    }

}
