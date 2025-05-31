package ndsware;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.Arrays;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

public class FileDataPanel extends JPanel {

    private static final Font FONT = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private static final int ROM_HEIGHT = 20;
    private static final String[] COLUMN_NAMES = { "Address", "Hex", "ASCII" };
    private static final int[] PREFERRED_COLUMN_WIDTHS = { 100, 350, 150 };
    private static final int ROW_BYTE_LENGTH = 16;

    private JLabel titleLabel;
    private JTable dataTable;
    private DefaultTableModel dataTableModel;

    public FileDataPanel() {
        setLayout(new BorderLayout());

        titleLabel = new JLabel("no file selected");
        add(titleLabel, BorderLayout.NORTH);

        dataTableModel = new DefaultTableModel(COLUMN_NAMES, 0) {
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        dataTable = new JTable(dataTableModel);
        dataTable.setFillsViewportHeight(true);
        dataTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        dataTable.setFont(FONT);
        dataTable.setRowHeight(ROM_HEIGHT);

        for (int i = 0; i < PREFERRED_COLUMN_WIDTHS.length; i++) {
            dataTable.getColumnModel().getColumn(i).setPreferredWidth(PREFERRED_COLUMN_WIDTHS[i]);
        }

        JScrollPane scrollPane = new JScrollPane(dataTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void update(String filePath, byte[] data) {
        titleLabel.setText("File: " + filePath);
        populateTable(data);
    }

    private void populateTable(byte[] data) {
        dataTableModel.setRowCount(0);

        int rows = (int) Math.ceil(data.length / (double) ROW_BYTE_LENGTH);
        for (int row = 0; row < rows; row++) {
            int rowStart = row * ROW_BYTE_LENGTH;
            int rowEnd = Math.min(rowStart + ROW_BYTE_LENGTH, data.length);
            byte[] rowData = Arrays.copyOfRange(data, rowStart, rowEnd);

            populateRow(rowStart, rowData);
        }
    }

    private void populateRow(int offset, byte[] rowData) {
        String address = String.format("%08X", offset);
        StringBuilder hex = new StringBuilder();
        StringBuilder ascii = new StringBuilder();

        for (int i = 0; i < rowData.length; i++) {
            byte b = rowData[i];
            hex.append(String.format("%02X ", b));
            ascii.append((b >= 32 && b < 127) ? (char) b : '.');
        }

        dataTableModel.addRow(new Object[] { address, hex.toString().trim(), ascii.toString() });
    }
}
