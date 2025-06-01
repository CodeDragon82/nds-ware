package ndsware;

import java.awt.BorderLayout;
import java.awt.Font;
import java.util.Arrays;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.GFilterTable;

public class FileDataPanel extends JPanel {

    private static final Font FONT = new Font(Font.MONOSPACED, Font.PLAIN, 16);
    private static final int[] PREFERRED_COLUMN_WIDTHS = { 100, 350, 150 };
    private static final int ROW_BYTE_LENGTH = 16;

    private JLabel titleLabel;
    private FileDataTableModel tableModel;
    private GFilterTable<FileDataRow> filterTable;

    public FileDataPanel() {
        setLayout(new BorderLayout());

        titleLabel = new JLabel("no file selected");
        add(titleLabel, BorderLayout.NORTH);

        DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer();
        cellRenderer.setFont(FONT);

        tableModel = new FileDataTableModel();
        filterTable = new GFilterTable<FileDataRow>(tableModel);
        filterTable.getTable().setFont(FONT);

        TableColumnModel columnModel = filterTable.getTable().getColumnModel();
        for (int i = 0; i < columnModel.getColumnCount(); i++) {
            columnModel.getColumn(i).setPreferredWidth(PREFERRED_COLUMN_WIDTHS[i]);
            columnModel.getColumn(i).setCellRenderer(cellRenderer);
        }

        add(filterTable, BorderLayout.CENTER);
    }

    public void update(String filePath, byte[] data) {
        titleLabel.setText("File: " + filePath);
        populateTable(data);
    }

    private void populateTable(byte[] data) {
        tableModel.clear();

        int rows = (int) Math.ceil(data.length / (double) ROW_BYTE_LENGTH);
        for (int row = 0; row < rows; row++) {
            int rowStart = row * ROW_BYTE_LENGTH;
            int rowEnd = Math.min(rowStart + ROW_BYTE_LENGTH, data.length);
            byte[] rowData = Arrays.copyOfRange(data, rowStart, rowEnd);

            populateRow(rowStart, rowData);
        }

        tableModel.fireTableDataChanged();
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

        FileDataRow newRow = new FileDataRow(address, hex.toString().trim(), ascii.toString());

        tableModel.addRow(newRow);
    }
}
