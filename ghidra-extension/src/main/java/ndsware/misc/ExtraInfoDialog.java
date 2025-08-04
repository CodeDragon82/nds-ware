package ndsware.misc;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.ScrollableTextArea;
import ghidra.util.Swing;

/**
 * A custom dialog prompt which can show additional context information in a
 * clean format.
 */
public class ExtraInfoDialog extends DialogComponentProvider {

    private boolean ok;

    protected ExtraInfoDialog(String title, String main_info, String extra_info) {
        super(title);

        ok = false;

        JPanel panel = new JPanel(new BorderLayout());

        JLabel questionLabel = new JLabel(main_info);
        questionLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        ScrollableTextArea scrollableTextArea = new ScrollableTextArea(extra_info);

        panel.add(questionLabel, BorderLayout.NORTH);
        panel.add(scrollableTextArea, BorderLayout.CENTER);
        addWorkPanel(panel);
    }

    protected void setOk() {
        ok = true;
    }

    protected boolean isOk() {
        return ok;
    }

    /**
     * Prompt the user with a question, including extra context info. The prompt has
     * a ok button with a given name, and a cancel button.
     * 
     * Returns true only if the ok button is clicked.
     */
    public static boolean ask(Component parent, String title, String question, String extra_info,
            String okButtonName) {
        return Swing.runNow(() -> {
            ExtraInfoDialog dialog = new ExtraInfoDialog(title, question, extra_info);

            JButton okButton = new JButton(okButtonName);
            okButton.addActionListener(e -> {
                dialog.setOk();
                dialog.close();
            });
            dialog.addButton(okButton);
            dialog.addCancelButton();

            DockingWindowManager.showDialog(parent, dialog);

            return dialog.isOk();
        });
    }

    public static boolean ask(Component parent, String title, String question, List<String> info_list,
            String okButtonName) {
        return ask(parent, title, question, String.join("\n", info_list), okButtonName);
    }

    /**
     * Prompt the user with some information, including extra context info.
     */
    public static void show(Component parent, String title, String statement, String extra_info) {
        Swing.runNow(() -> {
            ExtraInfoDialog dialog = new ExtraInfoDialog(title, statement, extra_info);
            dialog.addDismissButton();

            DockingWindowManager.showDialog(parent, dialog);
        });
    }

    public static void show(Component parent, String title, String statement, List<String> info_list) {
        show(parent, title, statement, String.join("\n", info_list));
    }
}
