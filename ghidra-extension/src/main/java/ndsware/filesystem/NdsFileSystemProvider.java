package ndsware.filesystem;

import java.awt.BorderLayout;
import java.util.ArrayList;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import ghidra.framework.plugintool.Plugin;
import ndsware.parsers.Nds;
import ndsware.parsers.Nds.Directory;
import ndsware.parsers.Nds.File;
import ndsware.parsers.Nds.FileEntry;
import ndsware.parsers.Nds.FileNameTable;

public class NdsFileSystemProvider extends ComponentProvider {

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Show Files";
    private static String ERROR_MESSAGE = "Failed to parse the NDS file system: ";

    private JPanel panel;
    private JLabel errorLabel;
    private GTree tree;
    private FileNode treeRoot;
    private FileDataPanel fileDataPanel;

    private int fileIndex;

    public NdsFileSystemProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "NDS File System", owner);
        buildPanel();
        createMenuAction();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        treeRoot = new FileNode("Root");
        tree = new GTree(treeRoot);
        tree.setRootVisible(false);

        // If a file is selected, load the file data into the 'FileDataPanel'.
        tree.addGTreeSelectionListener(e -> {
            TreePath treePath = e.getNewLeadSelectionPath();
            if (treePath == null) {
                return;
            }

            FileNode fileNode = (FileNode) treePath.getLastPathComponent();
            if (fileNode != null && fileNode.isLeaf()) {
                fileDataPanel.update(fileNode.getDisplayText(), fileNode.getFile().data());
            }
        });

        errorLabel = new JLabel();
        fileDataPanel = new FileDataPanel();

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tree, fileDataPanel);

        panel.add(errorLabel, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);

        setVisible(true);
    }

    /*
     * Called when the program changes.
     * 
     * Parses the `.nds` file, extracts the file system, and loads the files/folders
     * in the `GTree`.
     */
    public void update(String ndsPath) {
        errorLabel.setText("");
        fileDataPanel.clear();
        treeRoot.removeAll();

        try {
            Nds nds = Nds.fromFile(ndsPath);

            Directory rootDirectory = nds.fileNameTable().directories().get(0);

            // The FAT should be read in reverse to the FNT.
            fileIndex = nds.fileAllocationTable().size() - 1;

            loadDirectory(nds.fileNameTable(), nds.files(), rootDirectory, treeRoot);
        } catch (Exception e) {
            errorLabel.setText(ERROR_MESSAGE + ndsPath + "\n" + e.getMessage());
        }
    }

    /*
     * Recursively loads files and folders into `FileNode`s and adds them to the
     * GTree.
     */
    private void loadDirectory(FileNameTable fileNameTable, ArrayList<File> files,
            Directory directory, FileNode directoryNode) {

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

            directoryNode.addNode(fileNode);
        }
    }

    /*
     * Adds the 'NDS File System' window as a "Show Files" option in the "NDS"
     * toolbar menu.
     */
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
