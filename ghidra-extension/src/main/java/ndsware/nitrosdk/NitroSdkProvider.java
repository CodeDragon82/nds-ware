package ndsware.nitrosdk;

import java.awt.BorderLayout;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
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
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class NitroSdkProvider extends ComponentProvider {

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Nitro SDK";
    private static String IMPORTED_NITRO_SDK_FOLDER = "nitro-sdk";

    private Project project;
    private Program program;
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
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        treeRoot = new LibraryNode("");
        tree = new GTree(treeRoot);
        tree.setRootVisible(false);

        JButton analyseButton = new JButton("Analyse");
        analyseButton.addActionListener((e) -> {
            Task task = new AnalyseLibraryTask(program, treeRoot);
            TaskLauncher.launch(task);
        });

        panel.add(tree, BorderLayout.CENTER);
        panel.add(analyseButton, BorderLayout.SOUTH);

        setVisible(true);
    }

    private void load() {

        DomainFolder projectFolder = project.getProjectData().getRootFolder();
        DomainFolder nitroSdkFolder = projectFolder.getFolder(IMPORTED_NITRO_SDK_FOLDER);

        loadLibrary(nitroSdkFolder, treeRoot);
    }

    private void loadLibrary(DomainFolder folder, LibraryNode node) {
        for (DomainFolder childFolder : folder.getFolders()) {
            LibraryNode childNode = new LibraryNode(childFolder.getName());
            node.addNode(childNode);

            loadLibrary(childFolder, childNode);
        }

        for (DomainFile childFile : folder.getFiles()) {
            LibraryNode childNode = new LibraryNode(childFile.getName());
            node.addNode(childNode);

            try {
                loadLibrary(childFile, childNode);
            } catch (VersionException | CancelledException | MemoryAccessException | IOException e) {
                Msg.showError(this, null, "Failed to load " + childFile.getName(), e.getMessage());
            }
        }
    }

    private void loadLibrary(DomainFile file, LibraryNode node)
            throws VersionException, CancelledException, IOException, MemoryAccessException {

        Program libraryProgram = (Program) file.getDomainObject(new Object(), false, false, monitor);
        Memory libraryMemory = libraryProgram.getMemory();

        for (Function function : libraryProgram.getFunctionManager().getFunctions(true)) {
            String functionName = function.getName();
            byte[] functionBytes = new byte[(int) function.getBody().getNumAddresses()];
            libraryMemory.getBytes(function.getBody().getMinAddress(), functionBytes);

            LibraryNode newNode = new LibraryNode(functionName, functionBytes, program.getSymbolTable());
            node.addNode(newNode);
        }
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

    public void update(Program newProgram) {
        this.program = newProgram;
        load();
    }
}
