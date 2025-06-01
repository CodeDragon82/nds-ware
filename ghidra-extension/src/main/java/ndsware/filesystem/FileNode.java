package ndsware.filesystem;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ndsware.parsers.Nds.File;

public class FileNode extends GTreeNode {
    private String name;
    private File file;

    public FileNode(String name) {
        this.name = name;
        this.file = null;
    }

    public void setFile(File file) {
        this.file = file;
    }

    public File getFile() {
        return this.file;
    }

    private long getFileSize() {
        long start = file.info().startOffset();
        long end = file.info().endOffset();

        return end - start;
    }

    @Override
    public Icon getIcon(boolean arg0) {
        return null;
    }

    @Override
    public String getName() {
        String fileString = this.name;

        if (file != null) {
            fileString += " - " + getFileSize() + "B";
        }

        return fileString;
    }

    @Override
    public String getToolTip() {
        return null;
    }

    @Override
    public boolean isLeaf() {
        return file != null;
    }
}
