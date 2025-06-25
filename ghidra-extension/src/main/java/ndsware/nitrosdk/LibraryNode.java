package ndsware.nitrosdk;

import java.awt.Color;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class LibraryNode extends GTreeNode {

    private static final Icon greenCircle = new CircleIcon(8, Color.green);
    private static final Icon hollowCircle = new CircleIcon(8, Color.gray);

    // Reference to the program symbol table.
    private SymbolTable symbolTable;

    private String name;
    private byte[] bytes;

    public LibraryNode(String name) {
        this.name = name;
    }

    public LibraryNode(String name, byte[] bytes, SymbolTable symbolTable) {
        this.name = name;
        this.bytes = bytes;
        this.symbolTable = symbolTable;
    }

    public String getFunctionName() {
        return name;
    }

    public byte[] getFunctionBytes() {
        return bytes;
    }

    /**
     * Returns the function address if found, or null if not found.
     */
    public Address getFunctionAddress() {
        if (symbolTable == null) {
            return null;
        }

        List<Symbol> functionSymbols = symbolTable.getGlobalSymbols(name);

        if (functionSymbols.isEmpty()) {
            return null;
        }

        return functionSymbols.getFirst().getAddress();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Icon getIcon(boolean arg0) {

        // If libraryNode is a not a function, return null.
        if (symbolTable == null) {
            return null;
        }

        List<Symbol> functionSymbols = symbolTable.getGlobalSymbols(name);

        if (functionSymbols.isEmpty()) {
            return hollowCircle;
        }

        return greenCircle;
    }

    @Override
    public String getToolTip() {

        // If libraryNode is a not a function, return null.
        if (symbolTable == null) {
            return null;
        }

        List<Symbol> functionSymbols = symbolTable.getGlobalSymbols(name);

        if (functionSymbols.isEmpty()) {
            return "Not Found";
        }

        Address functionAddress = functionSymbols.getFirst().getAddress();
        String functionOffset = "0x" + Integer.toHexString((int) functionAddress.getOffset());

        return "Found at " + functionOffset;
    }

    @Override
    public boolean isLeaf() {
        return bytes != null;
    }
}
