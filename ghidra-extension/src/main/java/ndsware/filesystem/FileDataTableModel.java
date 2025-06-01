package ndsware.filesystem;

import java.util.ArrayList;
import java.util.List;

import javax.swing.table.AbstractTableModel;

import docking.widgets.table.RowObjectTableModel;

public class FileDataTableModel extends AbstractTableModel implements RowObjectTableModel<FileDataRow> {

    private final String[] columnNames = { "Address", "Hex", "ASCII" };
    private final List<FileDataRow> rows = new ArrayList<>();

    public void addRow(FileDataRow newRow) {
        rows.add(newRow);
    }

    public void clear() {
        rows.clear();
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return columnNames[columnIndex];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        FileDataRow row = rows.get(rowIndex);
        return switch (columnIndex) {
            case 0 -> row.getAddress();
            case 1 -> row.getHex();
            case 2 -> row.getAscii();
            default -> null;
        };
    }

    @Override
    public Object getColumnValueForRow(FileDataRow row, int columnIndex) {
        return switch (columnIndex) {
            case 0 -> row.getAddress();
            case 1 -> row.getHex();
            case 2 -> row.getAscii();
            default -> null;
        };
    }

    @Override
    public List<FileDataRow> getModelData() {
        return rows;
    }

    @Override
    public String getName() {
        return "File Data";
    }

    @Override
    public int getRowIndex(FileDataRow row) {
        return rows.indexOf(row);
    }

    @Override
    public FileDataRow getRowObject(int rowIndex) {
        return rows.get(rowIndex);
    }

}
