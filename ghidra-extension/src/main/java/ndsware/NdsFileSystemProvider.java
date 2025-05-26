package ndsware;

import java.awt.BorderLayout;

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
import ndsware.parsers.Nds.FileEntry;
import ndsware.parsers.Nds.FileNameTable;

public class NdsFileSystemProvider extends ComponentProvider {

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Show Files";
    private static String ERROR_MESSAGE = "Failed to parse the NDS file system: ";

    private JPanel panel;
    private JLabel errorLabel;
    private JTree tree;
    private DefaultTreeModel treeModel;
    private DefaultMutableTreeNode treeRoot;

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

            loadDirectory(nds.fileNameTable(), rootDirectory, treeRoot);
        } catch (Exception e) {
            errorLabel.setText(ERROR_MESSAGE + ndsPath);
        }

        treeModel.reload(treeRoot);
    }

    private void loadDirectory(FileNameTable fileNameTable, Directory directory, DefaultMutableTreeNode directoryNode) {

        // The last entry in a directory is always empty.
        directory.files().removeLast();

        for (FileEntry fileEntry : directory.files()) {
            DefaultMutableTreeNode fileNode = new DefaultMutableTreeNode(fileEntry.name());

            if (fileEntry.isDirectory()) {
                int next_directory_index = fileEntry.directoryId() & 0xFFF;
                Directory next_directory = fileNameTable.directories().get(next_directory_index);
                loadDirectory(fileNameTable, next_directory, fileNode);
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
