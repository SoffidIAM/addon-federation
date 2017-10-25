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
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.ConditionType;

//Per a attributs i les seues condicion
public class AttPolicy extends AtributFederationElementFillTree {

	public AttPolicy(Component contenidor, Attribute atribut, AttributePolicyCondition condPare, boolean principal)
			throws Exception {
		super(contenidor, atribut, condPare, principal);
		//setCondicioAtributPare(condicioPare);
		if (getBotoEsborrar() != null) {
			getBotoEsborrar().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					removeAllAttributeChildrenCondition();
					detach();
				}
			});
		}

		if (getBotoSelecionaAtribut() != null) {
			final AttPolicy parent = this;
			getBotoSelecionaAtribut().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					Object[] dades = { parent, getAttributeName(), getAttributeShortName(),
							getAttributeOID() };
					Events.postEvent("onInicia", Executions.getCurrent().getDesktop().getPage("federacioAtributs").getFellow("esquema"), dades);
				}
			});
		}
		addEventListener("onActualitza", new org.zkoss.zk.ui.event.EventListener() {
			public void onEvent(Event event) throws Exception {
				Attribute sel = (Attribute) event.getData();
				// Ho posem graficament
				setAttributeName(sel.getName());
				setAttributeShortName(sel.getShortName());
				setAttributeOID(sel.getOid());
				// Guardem l'atribut a la condició
				setAtribut(sel);
			}
		});

	}

	public AttPolicy(Component contenidor, AttributePolicyCondition atributCondition, boolean principal) {
		super(contenidor, atributCondition, null, principal);
		//setCondicioAtributPare(atributConditionPare);
		if (getBotoEsborrar() != null) {
			getBotoEsborrar().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					removeAsChildrenAttributeCondition();
					detach();
				}
			});
		}
		if (getBotoAfegir() != null) {
			getBotoAfegir().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					// Condició secundària
					if (getFila().getTreechildren() == null) {
						getFila().appendChild(new Treechildren());
					}
					//condicio filla
					AttributePolicyCondition novaCond = new AttributePolicyCondition(
					com.soffid.iam.addons.federation.common.ConditionType.ANY, "", true);
					// I l'afegim con a filla nostra
					Collection fills = getCondicio().getChildrenCondition();
					if (fills == null) {
						fills = new ArrayList();
						getCondicio().setChildrenCondition(fills);
					}
					fills.add(novaCond);
					// Component de l'arbre
					AttPolicy nova = new AttPolicy(getFila().getTreechildren(), novaCond, false);
					//ens afegim con a condició pare de la nova
					nova.setAttributePolicyConditionPare(getAttributePolicyCondition());
					// Heretem atribut del pare
					novaCond.setAttribute(getAttributePolicyCondition().getAttribute()); 
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
			final AttPolicy parent = this;
			getBotoSelecionaAtribut().addEventListener("onClick", new org.zkoss.zk.ui.event.EventListener() {
				public void onEvent(Event event) throws Exception {
					Object[] dades = { parent, getAttributeName(), "", "" };
					Events.postEvent("onInicia", Executions.getCurrent().getDesktop().getPage("federacioAtributs").getFellow("esquema"), dades);
				}
			});
		}

		addEventListener("onActualitza", new org.zkoss.zk.ui.event.EventListener() {
			public void onEvent(Event event) throws Exception {
				if (event.getData() instanceof String[]) {
					String[] dades = (String[]) event.getData();
					setAttributeName(dades[0]);
				}
			}
		});

		// mirem si té condicions filles
		if (atributCondition.getChildrenCondition() != null) {

			// Pare és mainCond
			if (getFila().getTreechildren() == null) {
				getFila().appendChild(new Treechildren());
			}
			for (Iterator it = atributCondition.getChildrenCondition().iterator(); it.hasNext();) {
				Object elem = it.next();
				if (elem instanceof AttributePolicyCondition) {
					AttributePolicyCondition pc = (AttributePolicyCondition) elem;
					AttPolicy nova = new AttPolicy(getFila().getTreechildren(), pc, false); // no principal
					nova.setAttributePolicyConditionPare(atributCondition);
				}
			}
		}

	}

}
