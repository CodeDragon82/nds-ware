package ndsware.nitrosdk;

import javax.swing.JCheckBox;

import docking.widgets.tree.DefaultGTreeFilterProvider;
import docking.widgets.tree.GTree;
import docking.widgets.tree.support.GTreeFilter;

public class LibraryFilterProvider extends DefaultGTreeFilterProvider {

    private JCheckBox hideMissingCheckBox;

    public LibraryFilterProvider(GTree gTree, JCheckBox hideMissingCheckBox) {
        super(gTree);

        this.hideMissingCheckBox = hideMissingCheckBox;
        this.hideMissingCheckBox.addActionListener(e -> {

            // Filters are only used if the filter field text is not empty.
            if (this.getFilterText().isEmpty()) {
                this.setFilterText("*");
            }

            gTree.filterChanged();
        });
    }

    @Override
    public GTreeFilter getFilter() {
        GTreeFilter baseFilter = super.getFilter();
        if (baseFilter == null) {
            return null;
        }
        return new LibraryFilter(baseFilter, hideMissingCheckBox.isSelected());
    }
}
