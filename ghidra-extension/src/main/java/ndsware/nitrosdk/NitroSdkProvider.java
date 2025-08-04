package ndsware.nitrosdk;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;
import ndsware.nitrosdk.tasks.ImportTask;
import ndsware.nitrosdk.tasks.LoadTask;
import ndsware.nitrosdk.tasks.SearchTask;

public class NitroSdkProvider extends ComponentProvider {

    private static final String TOOL_NAME = "Nitro SDK";
    private static final String MENU_NAME = "NDS";
    private static final String MENU_OPTION = "Nitro SDK";
    public static final String IMPORTED_NITRO_SDK_FOLDER = "nitro-sdk";
    private static final String HIDE_MISSING_FUNCTIONS_CHECKBOX = "Hide Missing Functions";

    private Project project;
    private DomainFolder projectFolder;
    private Program program;

    private GTree tree;
    private LibraryNode treeRoot;

    private JPanel panel;

    public NitroSdkProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), TOOL_NAME, owner);

        project = plugin.getTool().getProject();
        projectFolder = project.getProjectData().getRootFolder();

        buildPanel();
        createMenuAction();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        JCheckBox hideMissingCheckBox = new JCheckBox(HIDE_MISSING_FUNCTIONS_CHECKBOX);

        treeRoot = new LibraryNode("");
        tree = new GTree(treeRoot);
        tree.setRootVisible(false);
        tree.setFilterProvider(new LibraryFilterProvider(tree, hideMissingCheckBox));
        tree.addGTreeSelectionListener((e) -> {
            TreePath treePath = e.getPath();
            if (treePath == null) {
                return;
            }

            LibraryNode libraryNode = (LibraryNode) treePath.getLastPathComponent();
            if (true) {
                GoToService goToService = getTool().getService(GoToService.class);
                goToService.goTo(libraryNode.getFunctionAddress());
            }
        });

        JButton importButton = new JButton("Import");
        importButton.addActionListener(e -> {

            ImportTask task = new ImportTask(projectFolder);
            task.addTaskListener(new TaskListener() {

                @Override
                public void taskCompleted(Task arg0) {
                    loadNitroSdk();
                }

                @Override
                public void taskCancelled(Task arg0) {
                }

            });
            if (task.setup()) {
                TaskLauncher.launch(task);
            }
        });

        JButton analyseButton = new JButton("Analyse");
        analyseButton.addActionListener(e -> {
            Task task = new SearchTask(program, treeRoot);
            TaskLauncher.launch(task);
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(importButton);
        buttonPanel.add(analyseButton);
        buttonPanel.add(hideMissingCheckBox);

        panel.add(tree, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        setVisible(true);
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

        loadNitroSdk();
    }

    private void loadNitroSdk() {
        Task loadLibraryTask = new LoadTask(program, projectFolder.getFolder(IMPORTED_NITRO_SDK_FOLDER),
                treeRoot);
        TaskLauncher.launch(loadLibraryTask);
    }
}
