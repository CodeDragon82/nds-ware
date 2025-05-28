package ndsware;

import java.awt.BorderLayout;
import java.util.ArrayList;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.framework.plugintool.Plugin;
import ndsware.parsers.Nds;
import ndsware.parsers.Nds.Directory;
import ndsware.parsers.Nds.File;
import ndsware.parsers.Nds.FileEntry;
import ndsware.parsers.Nds.FileNameTable;

public class NdsFileSystemProvider extends ComponentProvider {

    private class FileNode extends DefaultMutableTreeNode {
        private File file;

        public FileNode(String name) {
            super(name);
            this.file = null;
        }

        public void setFile(File file) {
            this.file = file;
        }

        private long getFileSize() {
            long start = file.info().startOffset();
            long end = file.info().endOffset();

            return end - start;
        }

        @Override
        public String toString() {
            String fileString = getUserObject().toString();

            if (file != null) {
                fileString += " - " + getFileSize() + "B";
            }

            return fileString;
        }
    }

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Show Files";
    private static String ERROR_MESSAGE = "Failed to parse the NDS file system: ";

    private JPanel panel;
    private JLabel errorLabel;
    private JTree tree;
    private DefaultTreeModel treeModel;
    private DefaultMutableTreeNode treeRoot;

    private int fileIndex;

    public NdsFileSystemProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "NDS Files", owner);
        buildPanel();
        createMenuAction();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        treeRoot = new DefaultMutableTreeNode("Root");
        treeModel = new DefaultTreeModel(treeRoot);
        tree = new JTree(treeModel);

        tree.setRootVisible(false);

        JScrollPane treeScrollPane = new JScrollPane(tree);
        errorLabel = new JLabel();

        panel.add(errorLabel, BorderLayout.NORTH);
        panel.add(treeScrollPane, BorderLayout.CENTER);

        setVisible(true);
    }

    public void updateTree(String ndsPath) {
        errorLabel.setText("");
        treeRoot.removeAllChildren();

        try {
            Nds nds = Nds.fromFile(ndsPath);

            Directory rootDirectory = nds.fileNameTable().directories().get(0);

            fileIndex = nds.fileAllocationTable().size() - 1;

            loadDirectory(nds.fileNameTable(), nds.files(), rootDirectory, treeRoot);
        } catch (Exception e) {
            errorLabel.setText(ERROR_MESSAGE + ndsPath);
        }

        treeModel.reload(treeRoot);
    }

    private void loadDirectory(FileNameTable fileNameTable, ArrayList<File> files,
            Directory directory, DefaultMutableTreeNode directoryNode) {

        for (int i = directory.files().size() - 2; i >= 0; i--) {
            FileEntry fileEntry = directory.files().get(i);
            FileNode fileNode = new FileNode(fileEntry.name());

            if (fileEntry.isDirectory()) {
                int next_directory_index = fileEntry.directoryId() & 0xFFF;
                Directory next_directory = fileNameTable.directories().get(next_directory_index);
                loadDirectory(fileNameTable, files, next_directory, fileNode);
            } else {
                fileNode.setFile(files.get(fileIndex));
                fileIndex -= 1;
            }

            directoryNode.add(fileNode);
        }
    }

    private void createMenuAction() {
        DockingAction showFilesAction = new DockingAction(MENU_OPTION, this.getOwner()) {

            @Override
            public void actionPerformed(ActionContext content) {
                setVisible(true);
            }
        };

        showFilesAction.setMenuBarData(new MenuData(new String[] { MENU_NAME, MENU_OPTION }));
        showFilesAction.setEnabled(true);

        this.getTool().addAction(showFilesAction);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
