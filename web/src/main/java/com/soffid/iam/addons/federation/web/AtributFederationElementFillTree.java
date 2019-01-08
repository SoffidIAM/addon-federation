package com.soffid.iam.addons.federation.web;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.zkoss.zk.ui.Component;
import org.zkoss.zul.Div;
import org.zkoss.zul.Label;
import org.zkoss.zul.Listbox;
import org.zkoss.zul.Listitem;
import org.zkoss.zul.Textbox;
import org.zkoss.zul.Treecell;
import org.zkoss.zul.Treerow;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.event.EventListener;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.ConditionType;

public class AtributFederationElementFillTree extends FederationElementFillTree implements java.io.Serializable {

	private static final long serialVersionUID = 1L;

	Textbox attributeShortName, attributeOID;
	Label lattributeShortName, lattributeOID;
	private Listbox allow;

	private Listitem allowed = new Listitem(Messages.getString("AtributFederationElementFillTree.AllowedAccess"), new Boolean(true)); //$NON-NLS-1$
	private Listitem denied = new Listitem(Messages.getString("AtributFederationElementFillTree.DeniedAccess"), new Boolean(false)); //$NON-NLS-1$

	// Guardem els VO corresponents
	private AttributePolicy attributePolicy;
	private AttributePolicyCondition attributePolicyCondition, attributePolicyConditionPare;

	public AtributFederationElementFillTree() {
		super();
	}

	// Afegim una condició filla a la condició actual
	public void addChildrenAttributeCondition(AttributePolicyCondition condicioFilla) throws Exception {

		if (attributePolicyCondition == null)
			throw new Exception(Messages.getString("AtributFederationElementFillTree.AddConditionsError")); //$NON-NLS-1$

		Collection fills = attributePolicyCondition.getChildrenCondition();
		if (fills == null) {
			fills = new ArrayList();
			attributePolicyCondition.setChildrenCondition(fills);
		}
		fills.add(condicioFilla);

		return;
	}

	// Esborra les condicions filles (recursivament)
	private void removeChildren(Collection fills) {
		if (fills != null) {
			Iterator<AttributePolicyCondition> it = fills.iterator();
			while (it.hasNext()) {
				AttributePolicyCondition fill = it.next();
				removeChildren(fill.getChildrenCondition());
			}
		}
		return;
	}

	/**
	 * Esborra totes les condicions filles de l'atribut (quan s'esborra
	 * l'atribut)
	 * 
	 * @throws Exception
	 */
	public void removeAllAttributeChildrenCondition() throws Exception {
		if (attributePolicyConditionPare == null)
			throw new Exception(Messages.getString("AtributFederationElementFillTree.DeleteConditionsError")); //$NON-NLS-1$

		// només una condició pare que pot tindre molts de fills
		Collection fillsPare = attributePolicyConditionPare.getChildrenCondition();
		if (fillsPare != null) {
			// mirem els fills
			for (Iterator<AttributePolicyCondition> it = fillsPare.iterator(); it.hasNext();) {
				AttributePolicyCondition condicio = it.next();
				// Esborrem recursivament les condicions filles d'aquesta
				// condició
				removeChildren(condicio.getChildrenCondition());
			}
		}

	}

	// Ens esborrem de la condició pare
	public void removeAsChildrenAttributeCondition() throws Exception {
		if (attributePolicyConditionPare == null)
			throw new Exception(Messages.getString("AtributFederationElementFillTree.DeleteAttributeError")); //$NON-NLS-1$

		boolean trobat = false;

		Collection fillsPare = attributePolicyConditionPare.getChildrenCondition();
		if (fillsPare != null) {
			// No s'ha de comparar...
			if (fillsPare.contains(attributePolicyCondition)) {
				trobat = true;
				// Esborrem recursivament les condicions filles d'aquesta
				// condició
				removeChildren(attributePolicyCondition.getChildrenCondition());
				// I ens esborrem del pare
				fillsPare.remove(attributePolicyCondition);
				return;
			}
		}

		if (!trobat)
			throw new Exception(Messages.getString("AtributFederationElementFillTree.AttributeChildNotFound")); //$NON-NLS-1$
	}	
	
	public AtributFederationElementFillTree(Component contenidor, AttributePolicyCondition condicio, boolean principal) {
		this(contenidor, condicio, null, principal);

	}

	public AtributFederationElementFillTree(Component contenidor, AttributePolicyCondition condicio,
			AttributePolicyCondition condicioPare, boolean principal) {
		// Per al cas de les condicions d'atributs
		super(contenidor, condicio, condicioPare, principal, principal ? TIPUS_ELEMENT.ATTRIBUTE_CONDITION_MAIN
				: TIPUS_ELEMENT.ATTRIBUTE_CONDITION_CHILD);

		// guardem el VO
		this.attributePolicyCondition = condicio;
		this.attributePolicyConditionPare = condicioPare;

		// Posem el valor que en té la condició principal
		if (principal) {
			// Afegim condició allow/deny
			allow = new Listbox();
			allow.setWidth("150px"); //$NON-NLS-1$
			allow.setMold("select"); //$NON-NLS-1$
			allow.appendChild(allowed);
			allow.appendChild(denied);
			allow.setSelectedItem(Boolean.TRUE.equals(condicio.getAllow()) ? allowed : denied);
			
			// Afegim eventlistener per guardar valor
			allow.addEventListener("onSelect", new EventListener() { //$NON-NLS-1$
				public void onEvent(Event event) throws Exception {
					Listitem sel = allow.getSelectedItem();
					if (sel != null && sel.getValue() instanceof Boolean) {
						getAttributePolicyCondition().setAllow((Boolean) sel.getValue());
					}
				}
			});

			afegirPrimerElement(allow);
		}

		// Icona different
		setIcona("img/document-ca.png"); //$NON-NLS-1$
	}

	public AtributFederationElementFillTree(Component contenidor, Attribute atribut, boolean principal) throws Exception {
		this(contenidor, atribut, null, principal);
	}

	public AtributFederationElementFillTree(Component contenidor, Attribute atribut, AttributePolicyCondition condicioPare,
			boolean principal) throws Exception {

		if (atribut == null || condicioPare == null)
			throw new Exception(Messages.getString("AtributFederationElementFillTree.NullAttributeOrCondition")); //$NON-NLS-1$

		// guardem el tipus i el VO
		super.tipusElement = TIPUS_ELEMENT.ATTRIBUTE;
		this.attributePolicyConditionPare = condicioPare;
		// El guardem en la condició pare
		attributePolicyConditionPare.setAttribute(atribut);

		this.contenidor = contenidor;
		this.filera = new Treerow();
		// filera.setStyle("background-color: white;");

		// Camps de valor
		Div totes = new Div();
		totes.setSclass("div_condition"); //$NON-NLS-1$

		// Camps
		/*
		 * attributeId = new Textbox(atribut.getId().toString());
		 * attributeId.setReadonly(true); lattributeId = new
		 * Label("attributeId");
		 */
		attributeName = new Textbox(atribut.getName());
		attributeName.setDisabled(true);
		lattributeName = new Label("name"); //$NON-NLS-1$
		attributeShortName = new Textbox(atribut.getShortName());
		attributeShortName.setDisabled(true);
		lattributeShortName = new Label("shortName"); //$NON-NLS-1$
		attributeOID = new Textbox(atribut.getOid());
		attributeOID.setDisabled(true);
		lattributeOID = new Label("oid"); //$NON-NLS-1$

		// Afegim botó per seleccionar atribut
		botoSelecionaAtribut = new org.zkoss.zul.Button();
		botoSelecionaAtribut.setTooltiptext(Messages.getString("AtributFederationElementFillTree.SelectAttributeMessage")); //$NON-NLS-1$
		botoSelecionaAtribut.setSrc("img/atribut.png"); //$NON-NLS-1$

		// Les afegim

		/*
		 * totes.appendChild(lattributeId); totes.appendChild(attributeId);
		 */
//		totes.appendChild(lattributeShortName);
//		totes.appendChild(attributeShortName);
		totes.appendChild(lattributeName);
		totes.appendChild(attributeName);
//		totes.appendChild(lattributeOID);
//		totes.appendChild(attributeOID);
		// L'afegim al final
		totes.appendChild(botoSelecionaAtribut);

		// botó per esborrar
		botoEsborrar = new es.caib.zkib.zkiblaf.ImageClic();
		botoEsborrar.setSrc("~./img/list-remove.gif"); //$NON-NLS-1$
		botoEsborrar.setAlign("right"); //$NON-NLS-1$
		// només visible quan no és principal
		botoEsborrar.setVisible(!principal);
		

		// botó per afegir
		/*
		 * botoAfegir = new es.caib.zkib.zkiblaf.ImageClic();
		 * botoAfegir.setSrc("~./img/list-add.gif");
		 * botoAfegir.setAlign("right");
		 */

		Treecell tcAfegir = new Treecell();
		Treecell tcEsborrar = new Treecell();
		// tcAfegir.appendChild(botoAfegir);
		tcEsborrar.appendChild(botoEsborrar);

		// PART FINAL
		// Afegim els components
		Treecell tc_valors = new Treecell();
		tc_valors.setImage("img/document-a.png"); //$NON-NLS-1$
		tc_valors.appendChild(totes);

		// filera.appendChild(tc_condicio);
		filera.appendChild(tc_valors);
		filera.appendChild(tcAfegir);
		filera.appendChild(tcEsborrar);

		// titem = new Treeitem();
		super.appendChild(filera);

		// Lo insertamos gráficamente
		contenidor.insertBefore(this, null);
	}

	public String getAttributeName() {
		return attributeName != null ? attributeName.getValue() : ""; //$NON-NLS-1$
	}

	public String getAttributeShortName() {
		return attributeShortName != null ? attributeShortName.getValue() : ""; //$NON-NLS-1$
	}

	public String getAttributeOID() {
		return attributeOID != null ? attributeOID.getValue() : ""; //$NON-NLS-1$
	}

	public void setAttributeName(String attributeName) {
		this.attributeName.setValue(attributeName);
	}

	public void setAttributeShortName(String attributeShortName) {
		this.attributeShortName.setValue(attributeShortName);
	}

	public void setAttributeOID(String attributeOID) {
		this.attributeOID.setValue(attributeOID);
	}

	protected void comprovaCondicio(ConditionType tipusCondicio) {
		super.comprovaCondicio(tipusCondicio);

		// Amaguem el botó de seleccionar atribut (ja el tenim)
		// ups, i did it again...
		botoSelecionaAtribut.setVisible(false);
		// i el nom de l'atribut (ja és l'atribut actual)
		// s'haurà de tenir en compte...
		lattributeName.setVisible(false);
		attributeName.setVisible(false);
	}

	public Attribute getAtribut() throws Exception {
		if (getAttributePolicyConditionPare() != null) {
			return getAttributePolicyConditionPare().getAttribute();
		} else
			throw new Exception(Messages.getString("AtributFederationElementFillTree.UndefiniedPrincipalAttribute")); //$NON-NLS-1$
	}

	public void setAtribut(Attribute atribut) throws Exception {
		if (getAttributePolicyConditionPare() != null) {
			getAttributePolicyConditionPare().setAttribute(atribut);
		} else
			throw new Exception(Messages.getString("AtributFederationElementFillTree.UndefiniedPrincipalAttribute")); //$NON-NLS-1$
	}

	public AttributePolicyCondition getAttributePolicyCondition() {
		return attributePolicyCondition;
	}

	public AttributePolicyCondition getAttributePolicyConditionPare() {
		return attributePolicyConditionPare;
	}

	public void setAttributePolicyCondition(AttributePolicyCondition attributePolicyCondition) {
		this.attributePolicyCondition = attributePolicyCondition;
	}

	public void setAttributePolicyConditionPare(AttributePolicyCondition attributePolicyConditionPare) {
		this.attributePolicyConditionPare = attributePolicyConditionPare;
	}

	public AttributePolicyCondition guardaValorsCondicio(AttributePolicyCondition condicio) throws Exception {
		super.guardaValorsCondicio(condicio);

		// Afegim atribut allow de la condició principal
		if (getAttributePolicyConditionPare() != null) {//TODO: Verificar !!
			attributePolicyCondition.setAttribute(getAttributePolicyConditionPare().getAttribute());
		}
		attributePolicyCondition.setAllow(condicio.getAllow()); //TODO: correcte?
		// si som condició principal ja tendrim el allow establert pel listbox
		
		return attributePolicyCondition;
	}

	public AttributePolicy getAttributePolicy() {
		return attributePolicy;
	}

	public void setAttributePolicy(AttributePolicy attributePolicy) {
		this.attributePolicy = attributePolicy;
	}
	
	public Listbox getAllowListbox() {
		return allow;
	}

}
