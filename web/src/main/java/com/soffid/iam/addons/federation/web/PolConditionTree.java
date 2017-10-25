package com.soffid.iam.addons.federation.web;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.Events;
import org.zkoss.zul.Listitem;
import org.zkoss.zul.Treechildren;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.PolicyCondition;

public class PolConditionTree extends FederationElementFillTree {

	public PolConditionTree(Component contenidor, PolicyCondition condicio, boolean principal) {
		super(contenidor, condicio, null, principal);

		// Afegim les condicions FILLES si les té
		if (getCondicio().getChildrenCondition() != null && getCondicio().getChildrenCondition().size() != 0) {
			// Condició secundària
			if (getFila().getTreechildren() == null) {
				getFila().appendChild(new Treechildren());
			}

			for (Iterator it = getCondicio().getChildrenCondition().iterator(); it.hasNext();) {
				// Creen la nova condició
				PolicyCondition novacond = (PolicyCondition) it.next();
				// I l'afegim con a filla nostra
				Collection fills = novacond.getChildrenCondition();
				if (fills == null) {
					fills = new ArrayList();
					novacond.setChildrenCondition(fills);
				}
				//fills.add(novacond);
				// Component de l'arbre
				PolConditionTree nova = new PolConditionTree(getFila().getTreechildren(), novacond, false);
				//ens afegim con a condició pare de la nova
				nova.setCondicioPare(getCondicio());
			}
		}

		// Afegim event al botó esborrar
		if (getBotoEsborrar() != null)
			getBotoEsborrar().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					removeAsChildrenCondition(); //ens esborrem del pare (si en té)
					detach();
				}
			});

		if (getBotoAfegir() != null) {
			getBotoAfegir().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					// Condició secundària
					if (getFila().getTreechildren() == null) {
						getFila().appendChild(new Treechildren());
					}
					// Creen la nova condició
					PolicyCondition novacond = new PolicyCondition(com.soffid.iam.addons.federation.common.ConditionType.ANY, "");
					// I l'afegim con a filla nostra
					Collection fills = getCondicio().getChildrenCondition();
					if (fills == null) {
						fills = new ArrayList();
						getCondicio().setChildrenCondition(fills);
					}
					fills.add(novacond);
					// Component de l'arbre
					PolConditionTree nova = new PolConditionTree(getFila().getTreechildren(), novacond, false);
					//ens afegim con a condició pare de la nova
					nova.setCondicioPare(getCondicio());
				}
			});
		}

		getListbox().addEventListener("onSelect", new org.zkoss.zk.ui.event.EventListener() {
			public void onEvent(Event event) throws Exception {
				Listitem sel = getListbox().getSelectedItem();
				if (sel != null && sel.getValue() instanceof ConditionType) {
					comprovaCondicio((ConditionType) sel.getValue());
				}
			}
		});

		if (getBotoSelecionaAtribut() != null) {
			final PolConditionTree parent = this;
			getBotoSelecionaAtribut().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					Object[] dades = { parent, getAttributeName(), "", "" };
					Events.postEvent("onInicia", Executions.getCurrent().getDesktop().getPage("federacioAtributs").getFellow("esquema"), dades);
				}
			});
		}

		addEventListener("onActualitza", new org.zkoss.zk.ui.event.EventListener() {
			public void onEvent(Event event) throws Exception {
				Attribute sel = (Attribute) event.getData();
				// Ho posem graficament
				setAttributeName(sel.getName());
				// Guardem l'atribut a la condición
				getCondicio().setAttribute(sel);
			}
		});

	}

}
