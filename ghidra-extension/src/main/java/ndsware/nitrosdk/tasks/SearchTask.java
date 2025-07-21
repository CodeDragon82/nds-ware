package ndsware.nitrosdk.tasks;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ndsware.nitrosdk.LibraryNode;

/**
 * Searches the game binary for Nitro SDK functions, by matching the byte
 * signatures.
 */
public class SearchTask extends Task {

    // Address space to search in.
    private static final long MIN_OFFSET = 0x2000000;
    private static final long MAX_OFFSET = 0x2FFFFFF;

    private final Address minAddress;
    private final Address maxAddress;

    private final Program program;
    private final Memory memory;
    private final SymbolTable symbolTable;

    private final LibraryNode rootNode;

    public SearchTask(Program program, LibraryNode rootNode) {
        super("Finding and Labelling Nitro SDK Functions", true, true, true);
        this.program = program;
        this.memory = program.getMemory();
        this.symbolTable = program.getSymbolTable();

        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        minAddress = addressSpace.getAddress(MIN_OFFSET);
        maxAddress = addressSpace.getAddress(MAX_OFFSET);

        this.rootNode = rootNode;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        monitor.initialize(countFunctions(rootNode));

        analyseLibrary(rootNode, monitor);
    }

    /**
     * Find and label all functions from the given library within the binary.
     */
    private void analyseLibrary(LibraryNode node, TaskMonitor monitor) throws CancelledException {

        // Stop searching if the user cancels the task.
        if (monitor.isCancelled()) {
            return;
        }

        if (node.isLeaf()) {
            findAndLabelFunction(node, monitor);
            monitor.increment();
        } else {
            for (GTreeNode childNode : node.getChildren()) {
                analyseLibrary((LibraryNode) childNode, monitor);
            }
        }
    }

    private void findAndLabelFunction(LibraryNode library, TaskMonitor monitor) {
        monitor.setMessage("Searching for " + library.getFunctionName());

        if (isFound(library.getFunctionName())) {
            return;
        }

        Address functionAddress = memory.findBytes(minAddress, maxAddress, library.getFunctionBytes(), null, true,
                new ConsoleTaskMonitor());

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

    private boolean isFound(String functionName) {
        return symbolTable.getGlobalSymbols(functionName).size() != 0;
    }

    private int countFunctions(LibraryNode libraryNode) {
        if (libraryNode.isLeaf()) {
            return 1;
        }

        int count = 0;
        for (GTreeNode node : libraryNode.getChildren()) {
            count += countFunctions((LibraryNode) node);
        }
        return count;
    }

}
