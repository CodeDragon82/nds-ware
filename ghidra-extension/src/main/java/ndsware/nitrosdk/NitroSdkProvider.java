package ndsware.nitrosdk;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;

public class NitroSdkProvider extends ComponentProvider {

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Nitro SDK";
    public static String IMPORTED_NITRO_SDK_FOLDER = "nitro-sdk";

    private Project project;
    private DomainFolder projectFolder;
    private Program program;

    private GTree tree;
    private LibraryNode treeRoot;

    private JPanel panel;

    public NitroSdkProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "Nitro SDK", owner);

        project = plugin.getTool().getProject();
        projectFolder = project.getProjectData().getRootFolder();

        buildPanel();
        createMenuAction();
    }

    private void buildPanel() {
        panel = new JPanel(new BorderLayout());

        treeRoot = new LibraryNode("");
        tree = new GTree(treeRoot);
        tree.setRootVisible(false);
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
        importButton.addActionListener((e) -> {

            // If the Nitro SDK folder exists in project, ask the user if they want to
            // overwrite it.
            if (projectFolder.getFolder(IMPORTED_NITRO_SDK_FOLDER) != null) {
                int result = OptionDialog.showYesNoDialog(null, "Existing Nitro SDK",
                        "Nitro SDK has already been imported. Do you want to overwrite it?");
                if (result != OptionDialog.YES_OPTION) {
                    return;
                }
            }

            JFileChooser fileChooser = new JFileChooser();

            // Filter for ZIP files.
            FileNameExtensionFilter filter = new FileNameExtensionFilter("ZIP files", "zip");
            fileChooser.setFileFilter(filter);

            int result = fileChooser.showOpenDialog(null);
            if (result != JFileChooser.APPROVE_OPTION) {
                Msg.showError(this, null, "Invalid File", "Cannot import Nitro SDK from a non-ZIP file.");
                return;
            }

            Task task = new ImportLibraryTask(fileChooser.getSelectedFile(), projectFolder);
            task.addTaskListener(new TaskListener() {

                @Override
                public void taskCompleted(Task arg0) {
                    loadNitroSdk();
                }

                @Override
                public void taskCancelled(Task arg0) {
                }

            });
            TaskLauncher.launch(task);
        });

        JButton analyseButton = new JButton("Analyse");
        analyseButton.addActionListener((e) -> {
            Task task = new AnalyseLibraryTask(program, treeRoot);
            TaskLauncher.launch(task);
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(importButton);
        buttonPanel.add(analyseButton);

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
        Task loadLibraryTask = new LoadLibraryTask(program, projectFolder.getFolder(IMPORTED_NITRO_SDK_FOLDER),
                treeRoot);
        TaskLauncher.launch(loadLibraryTask);
    }
}
