package ndsware.nitrosdk;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;

public class LibraryNode extends GTreeNode {
    private String name;
    private byte[] bytes;

    public LibraryNode(String name) {
        this.name = name;
    }

    public LibraryNode(String name, byte[] bytes) {
        this.name = name;
        this.bytes = bytes;
    }

    public String getFunctionName() {
        return name;
    }

    public byte[] getFunctionBytes() {
        return bytes;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Icon getIcon(boolean arg0) {
        return null;
    }

    @Override
    public String getToolTip() {
        return null;
    }

    @Override
    public boolean isLeaf() {
        return bytes != null;
    }
}
