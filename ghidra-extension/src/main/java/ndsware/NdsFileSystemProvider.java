package ndsware;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.framework.plugintool.Plugin;

public class NdsFileSystemProvider extends ComponentProvider {

    private static String MENU_NAME = "NDS";
    private static String MENU_OPTION = "Show Files";

    private JPanel panel;

    public NdsFileSystemProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "NDS Files", owner);
        buildPanel();
        createMenuAction();
    }

    // Customize GUI
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        JTextArea textArea = new JTextArea(5, 25);
        textArea.setEditable(false);
        panel.add(new JScrollPane(textArea));
        setVisible(true);
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
