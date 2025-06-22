package ndsware.nitrosdk;

import java.awt.BorderLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class NitroSdkProvider extends ComponentProvider {

    private class LibraryNode extends GTreeNode {
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

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Nitro SDK";

    private Project project;
    private TaskMonitor monitor;

    private GTree tree;
    private LibraryNode treeRoot;

    private JPanel panel;

    public NitroSdkProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "Nitro SDK", owner);

        project = plugin.getTool().getProject();
        monitor = new ConsoleTaskMonitor();

        buildPanel();
        createMenuAction();
        load();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        treeRoot = new LibraryNode("Root");
        tree = new GTree(treeRoot);
        tree.setRootVisible(false);

        panel.add(tree);

        setVisible(true);
    }

    private void load() {
        DomainFile library = project.getProjectData().getRootFolder().getFolder("libmi.a")
                .getFolder("mi_memory.o")
                .getFile("mi_memory.o");
        try {
            loadLibrary(library);
        } catch (VersionException | CancelledException | MemoryAccessException | IOException err) {
            Msg.showError(this, null, "Failed to load " + library.getName(), err.getMessage());
        }
    }

    private List<LibraryFunction> loadLibrary(DomainFile library)
            throws VersionException, CancelledException, IOException, MemoryAccessException {
        ArrayList<LibraryFunction> libraryFunctions = new ArrayList<LibraryFunction>();

        Program libraryProgram = (Program) library.getDomainObject(new Object(), false, false, monitor);
        Memory libraryMemory = libraryProgram.getMemory();

        for (Function function : libraryProgram.getFunctionManager().getFunctions(true)) {
            String functionName = function.getName();
            byte[] functionBytes = new byte[(int) function.getBody().getNumAddresses()];
            libraryMemory.getBytes(function.getBody().getMinAddress(), functionBytes);
            libraryFunctions.add(new LibraryFunction(functionName, functionBytes));
        }

        Msg.showInfo(this, null, "Loaded library " + library.getName(),
                libraryFunctions.stream().map(f -> f.getName() + ": " + Arrays.toString(f.getBytes()))
                        .collect(Collectors.toList()));

        return libraryFunctions;
    }

    /*
     * Adds the 'Nitro SDK' window as a "Nitro SDK" option in the "NDS"
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
