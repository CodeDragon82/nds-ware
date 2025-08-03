package ndsware.nitrosdk.tasks;

import java.util.ArrayList;
import java.util.List;

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
import ndsware.misc.ExtraInfoDialog;
import ndsware.nitrosdk.LibraryNode;

/**
 * Searches the game binary for Nitro SDK functions, by matching the byte
 * signatures.
 */
public class SearchTask extends Task {

    private static final String TASK_TITLE = "Finding and Labelling Nitro SDK Functions";

    private static final String SEARCH_COMPLETE_DIALOG_TITLE = "Nitro SDK Search Complete";
    private static final String SEARCH_COMPLETE_DIALOG_MESSAGE = "Found and labelled %d new Nitro SDK functions in the ROM.";

    private static final String SEARCH_MESSAGE = "Searching for %s";
    private static final String LABEL_FAILED_ERROR = "Failed to label %s";

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
        super(TASK_TITLE, true, true, true);
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

        ArrayList<String> newFoundFunctions = new ArrayList<String>();
        analyseLibrary(rootNode, newFoundFunctions, monitor);

        ExtraInfoDialog.show(null, SEARCH_COMPLETE_DIALOG_TITLE,
                String.format(SEARCH_COMPLETE_DIALOG_MESSAGE, newFoundFunctions.size()),
                newFoundFunctions);
    }

    /**
     * Find and label all functions from the given library within the binary.
     */
    private void analyseLibrary(LibraryNode node, List<String> newFoundFunctions, TaskMonitor monitor)
            throws CancelledException {

        // Stop searching if the user cancels the task.
        if (monitor.isCancelled()) {
            return;
        }

        if (node.isLeaf()) {
            if (findAndLabelFunction(node.getFunctionName(), node.getFunctionBytes(), monitor)) {
                newFoundFunctions.add(node.getFunctionName());
            }
            monitor.increment();
        } else {
            for (GTreeNode childNode : node.getChildren()) {
                analyseLibrary((LibraryNode) childNode, newFoundFunctions, monitor);
            }
        }
    }

    /**
     * Returns true if the library function was found and labelled successfully, and
     * hadn't been found previously.
     */
    private boolean findAndLabelFunction(String functionName, byte[] functionSignature, TaskMonitor monitor) {
        monitor.setMessage(String.format(SEARCH_MESSAGE, functionName));

        if (isFound(functionName)) {
            return false;
        }

        Address functionAddress = memory.findBytes(minAddress, maxAddress, functionSignature, null, true,
                new ConsoleTaskMonitor());

        if (functionAddress == null) {
            return false;
        }

        int transactionID = program.startTransaction("Label " + functionName);
        boolean success = false;
        try {
            symbolTable.createLabel(functionAddress, functionName, SourceType.USER_DEFINED);
            success = true;
        } catch (InvalidInputException e) {
            monitor.setMessage(String.format(LABEL_FAILED_ERROR, functionName));
        }
        program.endTransaction(transactionID, success);

        return success;
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
