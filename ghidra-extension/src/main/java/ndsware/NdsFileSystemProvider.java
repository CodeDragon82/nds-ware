package ndsware;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;

public class NdsFileSystemProvider extends ComponentProvider {

    private JPanel panel;

    public NdsFileSystemProvider(Plugin plugin, String owner) {
        super(plugin.getTool(), "NDS Files", owner);
        buildPanel();
    }

    // Customize GUI
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        JTextArea textArea = new JTextArea(5, 25);
        textArea.setEditable(false);
        panel.add(new JScrollPane(textArea));
        setVisible(true);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }
}
