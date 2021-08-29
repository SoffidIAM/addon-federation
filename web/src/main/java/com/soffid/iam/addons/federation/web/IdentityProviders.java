package com.soffid.iam.addons.federation.web;

import java.util.Arrays;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.HtmlBasedComponent;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zul.Div;

import es.caib.zkib.component.DataTable;
import es.caib.zkib.component.DataTree2;
import es.caib.zkib.component.Form2;
import es.caib.zkib.zkiblaf.Missatgebox;

public class IdentityProviders extends Div {

	public void displayRemoveButton(Component lb, boolean display) {
		HtmlBasedComponent d = (HtmlBasedComponent) lb.getNextSibling();
		if (d != null && d instanceof Div) {
			d =  (HtmlBasedComponent) d.getFirstChild();
			if (d != null && "deleteButton".equals(d.getSclass())) {
				d.setVisible(display);
			}
		}
	}
	
	public void multiSelect(Event event) {
		DataTable lb = (DataTable) event.getTarget();
		displayRemoveButton( lb, lb.getSelectedIndexes() != null && lb.getSelectedIndexes().length > 0);
	}

	public void deleteSelected(Event event0) {
		Component b = event0.getTarget();
		final Component lb = b.getParent().getPreviousSibling();
		if (lb instanceof DataTable) {
			final DataTable dt = (DataTable) lb;
			if (dt.getSelectedIndexes() == null || dt.getSelectedIndexes().length == 0) return;
			String msg = dt.getSelectedIndexes().length == 1 ? 
					Labels.getLabel("common.delete") :
					String.format(Labels.getLabel("common.deleteMulti"), dt.getSelectedIndexes().length);
				
			Missatgebox.confirmaOK_CANCEL(msg, 
					(event) -> {
						if (event.getName().equals("onOK")) {
							dt.delete();
							displayRemoveButton(lb, false);
						}
					});
		}
	}

	public void select(Event event) {
		ProviderHandler frame = getFrame();
		DataTable dt = (DataTable) getFellow("listbox");
		int position = dt.getSelectedIndex();
		DataTree2 tree = (DataTree2) frame.getFellow("listbox");
		int[] current = tree.getSelectedItem();
		if (current != null) {
			int[] next = Arrays.copyOf(current, current.length+1);
			next[current.length] = position;
			tree.setSelectedIndex(next);
		}
	}
	
	public void addNew(Event event) throws Exception {
		getFrame().addNewIdentityProvider();
	}
	
	ProviderHandler getFrame() {
		return (ProviderHandler) getPage().getFellow("frame");
	}
}
