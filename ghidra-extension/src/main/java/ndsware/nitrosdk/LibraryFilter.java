package ndsware.nitrosdk;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeFilter;

public class LibraryFilter implements GTreeFilter {

    private final GTreeFilter baseFilter;
    private final boolean hideMissingFunctions;

    public LibraryFilter(GTreeFilter treeFilter, boolean hideMissingFunctions) {
        this.baseFilter = treeFilter;
        this.hideMissingFunctions = hideMissingFunctions;
    }

    @Override
    public boolean acceptsNode(GTreeNode node) {
        boolean accept = this.baseFilter.acceptsNode(node);
        if (hideMissingFunctions) {

            // Check if function is found.
            accept &= ((LibraryNode) node).getFunctionAddress() != null;
        }
        return accept;
    }

    @Override
    public boolean showFilterMatches() {
        return this.baseFilter.showFilterMatches();
    }

}
