package com.soffid.iam.addons.federation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.zkoss.zk.ui.Component;
import org.zkoss.zul.Button;
import org.zkoss.zul.Checkbox;
import org.zkoss.zul.Div;
import org.zkoss.zul.Label;
import org.zkoss.zul.Listbox;
import org.zkoss.zul.Listitem;
import org.zkoss.zul.Textbox;
import org.zkoss.zul.Treecell;
import org.zkoss.zul.Treeitem;
import org.zkoss.zul.Treerow;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import es.caib.zkib.zkiblaf.ImageClic;
import es.caib.zkib.zkiblaf.Missatgebox;

/**
 * Classe gràfica per implementar elements de Federació d'identitats.
 * 
 * by Alejandro Usero Ruiz - 09/05/2012
 * 
 * @author u88683
 * 
 */
public class FederationElementFillTree extends Treeitem implements java.io.Serializable {

	private static final long serialVersionUID = 1L;

	protected Component contenidor; // Contenedor gráfico de filas
	protected Treerow filera;
	protected ImageClic botoEsborrar;
	protected ImageClic botoAfegir;
	protected Listbox lb_tipusCondicio;
	// protected Treeitem titem;
	private Treecell tc_valors; // per indicar la icona corresponent
	private Div totes;

	// Botó per seleccionar atribut
	protected org.zkoss.zul.Button botoSelecionaAtribut;

	// Elements de valor (segons tipus)
	protected Textbox value, regex, nameId, attributeNameFormat, groupId, nameIdFormat, script, attributeName, attributeValue,
			attributeValueRegex;
	protected Label lvalue, lregex, lnameId, lattributeNameFormat, lgroupId, lnameIdFormat, lscript, lattributeName, lattributeValue,
			lattributeValueRegex, lignoreCase, lnegativeCondition;
	private Checkbox ignoreCase, negativeCondition;
	private Component[] totCamp, labelTotCamp;

	private HashMap<ConditionType, List> campsVisibles;

	public FederationElementFillTree() {
		super();
	}

	public enum TIPUS_ELEMENT {
		POLICY_CONDITION_MAIN, POLICY_CONDITION_CHILD, ATTRIBUTE, ATTRIBUTE_CONDITION_MAIN, ATTRIBUTE_CONDITION_CHILD
	};

	// Per guardar el contingut
	protected TIPUS_ELEMENT tipusElement;
	private PolicyCondition condicio, condicioPare;

	// Afegim condicions filles a la condició actual
	public void addChildrenCondition(PolicyCondition condicioFilla) throws Exception {
		if (condicio == null)
			throw new Exception(Messages.getString("FederationElementFillTree.AddChildConditionError")); //$NON-NLS-1$

		Collection fills = condicio.getChildrenCondition();
		if (fills == null) {
			fills = new ArrayList();
			condicio.setChildrenCondition(fills);
		}
		fills.add(condicioFilla);

		return;
	}

	// Esborra les condicions filles (recursivament)
	private void removeChildren(PolicyCondition cond) {
		Collection fills = cond.getChildrenCondition();
		if (fills != null) {
			Iterator<PolicyCondition> it = fills.iterator();
			while (it.hasNext()) {
				PolicyCondition fill = it.next();
				removeChildren(fill);
				it.remove(); // l'esborrem
			}
		}

	}

	// Ens esborrem de la condició pare
	public void removeAsChildrenCondition() throws Exception {

		if (condicioPare == null) // si som principal... falla (arreglar!!)
			throw new Exception(Messages.getString("FederationElementFillTree.DeleteChildConditionError")); //$NON-NLS-1$

		boolean trobat = false;

		Collection fillsPare = condicioPare.getChildrenCondition();
		if (fillsPare != null) {
			// No s'ha de comparar... // Ens esborrem a nosaltres mateixos
			if (fillsPare.contains(condicio)) {
				trobat = true;
				// Esborrem recursivament les condicions filles d'aquesta
				// condició
				removeChildren(condicio);
				// I ens esborrem del pare
				fillsPare.remove(condicio);
				return;
			}
		}

		if (!trobat)
			throw new Exception(Messages.getString("FederationElementFillTree.ChildConditionNotFound")); //$NON-NLS-1$

		return;
	}

	public FederationElementFillTree(Component contenidor, PolicyCondition condicio, boolean principal) {
		this(contenidor, condicio, null, principal, principal ? TIPUS_ELEMENT.POLICY_CONDITION_MAIN
				: TIPUS_ELEMENT.POLICY_CONDITION_CHILD);
	}

	public FederationElementFillTree(Component contenidor, PolicyCondition condicio, PolicyCondition condicioPare, boolean principal) {
		this(contenidor, condicio, condicioPare, principal, principal ? TIPUS_ELEMENT.POLICY_CONDITION_MAIN
				: TIPUS_ELEMENT.POLICY_CONDITION_CHILD);
	}

	public FederationElementFillTree(Component contenidor, PolicyCondition condicio, boolean principal, TIPUS_ELEMENT tipus) {
		this(contenidor, condicio, null, principal, tipus);
	}

	public FederationElementFillTree(Component contenidor, PolicyCondition condicio, PolicyCondition condicioPare, boolean principal,
			TIPUS_ELEMENT tipus) {
		this.condicio = condicio;
		this.condicioPare = condicioPare;
		this.tipusElement = tipus;
		this.contenidor = contenidor;
		this.filera = new Treerow();
		// filera.setStyle("background-color: white;");

		this.lb_tipusCondicio = new Listbox();
		lb_tipusCondicio.setMold("select"); //$NON-NLS-1$

		Listitem condicioSeleccionada = null;

		for (Iterator it = ConditionType.literals().iterator(); it.hasNext();) {
			String name = (String) it.next();
			ConditionType c = ConditionType.fromString(name); // condició actual
			//TODO: No mostrem per ara les condicions de tipus basic:script
			if (c.equals(ConditionType.SCRIPT)) continue;
			Listitem l = new Listitem(name, c);
			lb_tipusCondicio.appendChild(l);
			if (c.equals(condicio.getType())) {
				// seleccionem el q toca
				condicioSeleccionada = l;
			}

		}
		// lb_tipusCondicio.setWidth("95%");
		if (condicioSeleccionada != null)
			lb_tipusCondicio.setSelectedItem(condicioSeleccionada);
		// lb_tipusCondicio.setStyle("width:200px");

		// Creem botó genèric per seleccionar atribut
		botoSelecionaAtribut = new org.zkoss.zul.Button();
		botoSelecionaAtribut.setTooltiptext(Messages.getString("FederationElementFillTree.SelectAttributeMessage")); //$NON-NLS-1$
		botoSelecionaAtribut.setSrc("img/atribut.png"); //$NON-NLS-1$

		// Camps de valor
		totes = new Div();
		totes.setSclass("div_condition"); //$NON-NLS-1$

		regex = new Textbox(condicio.getRegex());
		lregex = new Label("regex "); //$NON-NLS-1$
		nameId = new Textbox(condicio.getNameId());
		lnameId = new Label("nameId"); //$NON-NLS-1$
		attributeNameFormat = new Textbox(condicio.getAttributeNameFormat());
		lattributeNameFormat = new Label("attributeNameFormat"); //$NON-NLS-1$
		groupId = new Textbox(condicio.getGroupId());
		lgroupId = new Label("groupId"); //$NON-NLS-1$
		attributeName = new Textbox(condicio.getAttribute() != null ? condicio.getAttribute().getName() : ""); //$NON-NLS-1$

		attributeName.setDisabled(true);// es podrà seleccionar
		lattributeName = new Label("attributeName"); //$NON-NLS-1$
		// TODO: aqui hem de tindre en compte el tipus de condicio
		value = new Textbox(condicio.getValue());
		lvalue = new Label("Value"); //$NON-NLS-1$
		// Ficticis... QUE HEM DE FER??
		script = new Textbox(condicio.getValue()); // hem de fer un blob??
		script.setRows(4); //ho fem més gros
		script.setWidth("500px"); //$NON-NLS-1$
		lscript = new Label("script"); //$NON-NLS-1$
		nameIdFormat = new Textbox(condicio.getValue());
		lnameIdFormat = new Label("nameIdFormat"); //$NON-NLS-1$
		attributeValue = new Textbox(condicio.getValue());
		lattributeValue = new Label("attributeValue"); //$NON-NLS-1$
		attributeValueRegex = new Textbox(condicio.getValue());
		lattributeValueRegex = new Label("attributeValueRegex"); //$NON-NLS-1$

		// checkbox
		negativeCondition = new Checkbox("NOT");//"negativeCondition"); //$NON-NLS-1$
		lnegativeCondition = new Label(""); //$NON-NLS-1$
		Boolean neg = condicio.getNegativeCondition();
		negativeCondition.setChecked(neg != null ? neg : false);
		ignoreCase = new Checkbox("ignoreCase"); //$NON-NLS-1$
		// lignoreCase = new Label("ignoreCase");
		lignoreCase = new Label(""); //$NON-NLS-1$
		Boolean ign = condicio.getIgnoreCase();
		ignoreCase.setChecked(ign != null ? ign : false);

		totCamp = new Component[] { value, regex, nameId, attributeNameFormat, negativeCondition, ignoreCase, groupId, nameIdFormat,
				script, attributeName, attributeValue, attributeValueRegex, botoSelecionaAtribut };
		labelTotCamp = new Component[] { lvalue, lregex, lnameId, lattributeNameFormat, lnegativeCondition, lignoreCase, lgroupId,
				lnameIdFormat, lscript, lattributeName, lattributeValue, lattributeValueRegex, null };
		{
			campsVisibles = new HashMap();
			// TOTS obligatoris menys els indicats
			campsVisibles.put(ConditionType.ANY, Arrays.asList(new Component[] { negativeCondition}));
			campsVisibles.put(ConditionType.AND, Arrays.asList(new Component[] { negativeCondition}));
			campsVisibles.put(ConditionType.OR, Arrays.asList(new Component[] { negativeCondition}));
			// attributeNameFormat opcional
			campsVisibles.put(ConditionType.ATTRIBUTE_REQUESTER_STRING,
					Arrays.asList(new Component[] { negativeCondition, value, ignoreCase }));
			campsVisibles.put(ConditionType.ATTRIBUTE_ISSUER_STRING, Arrays.asList(new Component[] {negativeCondition,  value, ignoreCase }));
			campsVisibles.put(ConditionType.PRINCIPAL_NAME_STRING, Arrays.asList(new Component[] { negativeCondition, value, ignoreCase }));
			campsVisibles.put(ConditionType.AUTHENTICATION_METHOD_STRING, Arrays.asList(new Component[] { negativeCondition, value, ignoreCase }));
			campsVisibles.put(ConditionType.ATTRIBUTE_VALUE_STRING,
					Arrays.asList(new Component[] { negativeCondition, value, ignoreCase, attributeName, botoSelecionaAtribut }));
			campsVisibles.put(ConditionType.ATTRIBUTE_SCOPE_STRING,
					Arrays.asList(new Component[] { negativeCondition, value, ignoreCase, attributeName, botoSelecionaAtribut }));
			campsVisibles.put(ConditionType.ATTRIBUTE_REQUESTER_REGEX, Arrays.asList(new Component[] { negativeCondition, regex }));
			campsVisibles.put(ConditionType.ATTRIBUTE_ISSUER_REGEX, Arrays.asList(new Component[] { negativeCondition, regex }));
			campsVisibles.put(ConditionType.PRINCIPAL_NAME_REGEX, Arrays.asList(new Component[] { negativeCondition, regex }));
			campsVisibles.put(ConditionType.AUTHENTICATION_METHOD_REGEX, Arrays.asList(new Component[] { negativeCondition, regex }));
			campsVisibles.put(ConditionType.ATTRIBUTE_VALUE_REGEX,
					Arrays.asList(new Component[] { negativeCondition, attributeName, botoSelecionaAtribut, regex }));
			campsVisibles.put(ConditionType.ATTRIBUTE_SCOPE_REGEX,
					Arrays.asList(new Component[] { negativeCondition, attributeName, botoSelecionaAtribut, regex }));
			// NOTA: Script es guardarà en el value
			campsVisibles.put(ConditionType.SCRIPT, Arrays.asList(new Component[] { negativeCondition, script }));
			campsVisibles.put(ConditionType.ATTRIBUTE_REQUESTER_IN_ENTITY_GROUP, Arrays.asList(new Component[] { negativeCondition, groupId }));
			campsVisibles.put(ConditionType.ATTRIBUTE_ISSUER_IN_ENTITY_GROUP, Arrays.asList(new Component[] { negativeCondition, groupId }));
			campsVisibles.put(ConditionType.ATTRIBUTE_ISSUER_NAME_IDFORMAT_EXACT_MATCH,
					Arrays.asList(new Component[] { negativeCondition, nameIdFormat }));
			campsVisibles.put(ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH,
					Arrays.asList(new Component[] { negativeCondition, attributeName, botoSelecionaAtribut, attributeValue, attributeNameFormat }));
			campsVisibles.put(ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_REGEX_MATCH,
					Arrays.asList(new Component[] { negativeCondition, attributeName, botoSelecionaAtribut, attributeValueRegex, attributeNameFormat }));
			campsVisibles.put(ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_REGEX_MATCH,
					Arrays.asList(new Component[] { negativeCondition, attributeName, botoSelecionaAtribut, attributeValueRegex, attributeNameFormat }));
			campsVisibles.put(ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH,
					Arrays.asList(new Component[] { negativeCondition, attributeName, botoSelecionaAtribut, attributeValue, attributeNameFormat }));
			campsVisibles.put(ConditionType.ATTRIBUTE_REQUESTER_NAME_IDFORMAT_EXACT_MATCH,
					Arrays.asList(new Component[] { negativeCondition, nameIdFormat }));

		}
		
		// Posem el NOT com a primera condició
		totes.appendChild(lnegativeCondition);
		totes.appendChild(negativeCondition);


		totes.appendChild(lb_tipusCondicio);

		totes.appendChild(lvalue);
		totes.appendChild(value);
		totes.appendChild(lregex);
		totes.appendChild(regex);
		totes.appendChild(lnameId);
		totes.appendChild(nameId);
		totes.appendChild(lattributeNameFormat);
		totes.appendChild(attributeNameFormat);
		totes.appendChild(lignoreCase);
		totes.appendChild(ignoreCase);
		totes.appendChild(lgroupId);
		totes.appendChild(groupId);
		totes.appendChild(lattributeName);
		totes.appendChild(attributeName);
		totes.appendChild(botoSelecionaAtribut); // botó
		// aquestos son ficticis ??
		totes.appendChild(lscript); // value
		totes.appendChild(script); // value
		totes.appendChild(lnameIdFormat); // lattributeNameFormat ?
		totes.appendChild(nameIdFormat); // lattributeNameFormat ?
		totes.appendChild(lattributeValue); // value
		totes.appendChild(attributeValue); // value
		totes.appendChild(lattributeValueRegex); // value
		totes.appendChild(attributeValueRegex); // value

		// botó per esborrar
		botoEsborrar = new es.caib.zkib.zkiblaf.ImageClic();
		botoEsborrar.setSrc("~./img/list-remove.gif"); //$NON-NLS-1$
		botoEsborrar.setAlign("right"); //$NON-NLS-1$
		// només visible quan no és principal
		botoEsborrar.setVisible(!principal);

		// botó per afegir
		botoAfegir = new es.caib.zkib.zkiblaf.ImageClic();
		botoAfegir.setSrc("~./img/list-add.gif"); //$NON-NLS-1$
		botoAfegir.setAlign("right"); //$NON-NLS-1$

		Treecell tcAfegir = new Treecell();
		Treecell tcEsborrar = new Treecell();
		tcAfegir.appendChild(botoAfegir);
		tcEsborrar.appendChild(botoEsborrar);

		// Afegim els components
		tc_valors = new Treecell();
		tc_valors.setImage("img/document-c.png"); //$NON-NLS-1$
		tc_valors.appendChild(totes);

		// filera.appendChild(tc_condicio);
		filera.appendChild(tc_valors);
		filera.appendChild(tcAfegir);
		filera.appendChild(tcEsborrar);

		comprovaCondicio(condicio.getType());

		// titem = new Treeitem();
		appendChild(filera);

		// Lo insertamos gráficamente
		contenidor.insertBefore(this, null);
	}

	public void setIcona(String icona) {
		tc_valors.setImage(icona);
	}

	public void afegirElement(Component component) {
		totes.appendChild(component);
	}

	public void afegirPrimerElement(Component component) {
		Component primerFill = totes.getChildren() != null ? (Component) totes.getChildren().get(0) : null;
		totes.insertBefore(component, primerFill);
	}

	public Treeitem getFila() {
		return this;
	}

	public Component getContenidor() {
		return contenidor;
	}

	public ImageClic getBotoEsborrar() {
		return botoEsborrar;
	}

	public ImageClic getBotoAfegir() {
		return botoAfegir;
	}

	public ConditionType getCondicioSeleccionada() {
		return lb_tipusCondicio != null ? (ConditionType) lb_tipusCondicio.getSelectedItem().getValue() : null;
	}

	public Listbox getListbox() {
		return lb_tipusCondicio;
	}

	private void establixCondicio() {
		getCondicio().setType((ConditionType) lb_tipusCondicio.getSelectedItem().getValue());
	}

	protected void comprovaCondicio(ConditionType tipus) {
		// comprovem que si es canvia a tipus sense fills, no en tinga ja
		boolean condicioAmbFills = ConditionType.OR.equals(tipus) || ConditionType.AND.equals(tipus);
		if (!condicioAmbFills && getFila() != null && getFila().getTreechildren() != null
				&& !getFila().getTreechildren().getChildren().isEmpty()) {
			// Triem la basic:AND
			boolean trobat = false;
			for (int i = 0; !trobat && i < lb_tipusCondicio.getItemCount(); i++) {
				Listitem it = lb_tipusCondicio.getItemAtIndex(i);
				if (ConditionType.AND.equals(it.getValue())) {
					trobat = true;
					lb_tipusCondicio.setSelectedIndex(i);
				}
			}

			Missatgebox.confirmaOK(Messages.getString("FederationElementFillTree.NoChildAllowed")); //$NON-NLS-1$
			// if (trobat)
			comprovaCondicio((ConditionType) lb_tipusCondicio.getSelectedItem().getValue());

		} else {
			// Estil per a quan hem de posar script
			if (ConditionType.SCRIPT.equals(tipus)) {
				totes.setSclass("div_condition_script"); //$NON-NLS-1$
			} else {
				totes.setSclass("div_condition"); //$NON-NLS-1$
			}
			
			// Condició correcta
			// Mostrem els camps adients
			boolean[] bvisible = new boolean[totCamp.length];
			for (int i = 0; i < bvisible.length; i++) {
				bvisible[i] = false;
			}
			List visibles = (List) campsVisibles.get(tipus);
			if (visibles != null) {
				for (int i = 0; i < totCamp.length; i++) {
					bvisible[i] = visibles.contains(totCamp[i]);
				}
			}
			for (int i = 0; i < totCamp.length; i++) {
				if (totCamp[i] != null) {
					totCamp[i].setVisible(bvisible[i]);
					// les seves etiquetes (si la té)
					if (labelTotCamp[i] != null)
						labelTotCamp[i].setVisible(bvisible[i]);
				}
			}

			// mostrem el botó si pot tindre fills
			botoAfegir.setVisible(condicioAmbFills);
		}

		// Guardem el tipus de condicio seleccionat;
		establixCondicio();
	}

	public Button getBotoSelecionaAtribut() {
		return botoSelecionaAtribut;
	}

	public PolicyCondition getCondicio() {
		return condicio;
	}

	public PolicyCondition getCondicioPare() {
		return condicioPare;
	}

	public void setCondicioPare(PolicyCondition condicioPare) {
		this.condicioPare = condicioPare;
	}

	public PolicyCondition guardaValorsCondicio(PolicyCondition laCondicio) throws Exception {
		if (laCondicio == null)
			throw new Exception(Messages.getString("FederationElementFillTree.NullPoliticCondition")); //$NON-NLS-1$

		ConditionType tipusCondicio = laCondicio.getType();

		List camps = campsVisibles.get(tipusCondicio);

		// ID
		// no es fa res

		// TYPE: ja establert al seleccionar-lo (establixCondicio)
		/*if (sel != null && sel.getValue() != null && sel.getValue() instanceof ConditionType) {
			laCondicio.setType((ConditionType) sel.getValue());
		} else
			throw new Exception("No s'ha especificat el tipus de condició");
			*/

		// COMPROVEM QUE HAGIN TRIAT UN ATRIBUT (SI CAL)
		if (camps != null && camps.contains(attributeName)) {
			// Només als policyCondition.. als attributeCondition es copia del pare
			if (!(laCondicio instanceof AttributePolicyCondition) && attributeName.getValue() != null
					&& "".equals(attributeName.getValue().trim())) { //$NON-NLS-1$
				throw new Exception(Messages.getString("FederationElementFillTree.AttributeNotSelected")); //$NON-NLS-1$
			}
		}

		// VALUE
		// Per no posar el valor a null si ja en té valor atorgat..
		boolean teValue = false; 
		if (camps != null && camps.contains(value)) {
			// Si té atribut, comprovem que s'hagi posat valor
			if (attributeName.getValue() != null && !"".equals(attributeName.getValue().trim())) { //$NON-NLS-1$
				if (value.getValue() != null && "".equals(value.getValue().trim())) { //$NON-NLS-1$
					throw new Exception(Messages.getString("FederationElementFillTree.VoidAttributeValue")); //$NON-NLS-1$
				}
			}
			laCondicio.setValue(value.getValue());
			teValue = true;
		} else
			if (!teValue) laCondicio.setValue(null);
		
		// Camps ADDICIONALS que es guardan a VALUE (script, nameIdFormat, 	attributeValue, attributeValueRegex)
		// SCRIPT
		if (camps != null && camps.contains(script)) {
			laCondicio.setValue(script.getValue());
			teValue = true;
		} else
			if (!teValue) laCondicio.setValue(null);
		// nameIdFormat
		if (camps != null && camps.contains(nameIdFormat)) {
			laCondicio.setValue(nameIdFormat.getValue());
			teValue = true;
		} else
			if (!teValue) laCondicio.setValue(null);
		// attributeValue
		if (camps != null && camps.contains(attributeValue)) {
			laCondicio.setValue(attributeValue.getValue());
			teValue = true;
		} else
			if (!teValue) laCondicio.setValue(null);
		//attributeValueRegex
		if (camps != null && camps.contains(attributeValueRegex)) {
			laCondicio.setValue(attributeValueRegex.getValue());
			teValue = true;
		} else
			if (!teValue) laCondicio.setValue(null);

		// IGNORECASE
		if (camps != null && camps.contains(ignoreCase)) {
			laCondicio.setIgnoreCase(ignoreCase.isChecked());
		} else
			laCondicio.setIgnoreCase(null); // TODO: Corrrecte?? o posem false

		// GROUPID
		if (camps != null && camps.contains(groupId)) {
			laCondicio.setGroupId(groupId.getValue());
		} else
			laCondicio.setGroupId(null);

		// REGEX
		if (camps != null && camps.contains(regex)) {
			laCondicio.setRegex(regex.getValue());
		} else
			laCondicio.setRegex(null);

		// NAMEID
		if (camps != null && camps.contains(nameId)) {
			laCondicio.setNameId(nameId.getValue());
		} else
			laCondicio.setNameId(null);

		// ATTRIBUTENAMEFORMAT
		if (camps != null && camps.contains(attributeNameFormat)) {
			laCondicio.setAttributeNameFormat(attributeNameFormat.getValue());
		} else
			laCondicio.setAttributeNameFormat(null);

		// CHILDRENCONDITION
		// ja està.. en principi

		// NEGATIVECONDICION
		if (camps != null && camps.contains(negativeCondition)) {
			laCondicio.setNegativeCondition(negativeCondition.isChecked());
		} else
			laCondicio.setNegativeCondition(false); // posem false

		// ATTRIBUTEVALUE
		/*if (camps != null && camps.contains(attributeValue)) {
			condicio.setAttributeValue(attributeValue.getValue());
		} else
			condicio.setAttributeValue(null);
			*/

		return laCondicio;
	}

	public String getAttributeName() {
		return attributeName != null ? attributeName.getValue() : ""; //$NON-NLS-1$
	}

	public void setAttributeName(String attributeName) {
		this.attributeName.setValue(attributeName);
	}

	public TIPUS_ELEMENT getTipusElement() {
		return tipusElement;
	}

	public static Policy clonaPolicy(Policy original) {
		// copiem la base
		Policy nova = new Policy(original);

		if (original.getCondition() != null) {
			// el clonem
			PolicyCondition clonPC = clonaPC(original.getCondition());
			nova.setCondition(clonPC);
		}

		if (original.getAttributePolicy() != null) { // REVISAR
			Collection attPolicy = original.getAttributePolicy();
			ArrayList clonAttributePolicy = new ArrayList(attPolicy.size());
			for (Iterator<AttributePolicy> it = attPolicy.iterator(); it.hasNext();) {
				AttributePolicy attPolOriginal = it.next();
				// Creem el clon
				AttributePolicy clonAttPol = new AttributePolicy(attPolOriginal);
				if (attPolOriginal.getAttribute() != null)
					clonAttPol.setAttribute(new Attribute(attPolOriginal.getAttribute()));
				// clonem els AttributePolicyCondition de l'original
				AttributePolicyCondition clonAPC = clonaAC(attPolOriginal.getAttributePolicyCondition());
				clonAttPol.setAttributePolicyCondition(clonAPC);
				clonAttributePolicy.add(clonAttPol);
			}
			nova.setAttributePolicy(clonAttributePolicy);
		}

		return nova;
	}

	public static PolicyCondition clonaPC(PolicyCondition original) {
		PolicyCondition pc = new PolicyCondition(original);
		if (original.getAttribute() != null)
			pc.setAttribute(new Attribute(original.getAttribute()));
		if (original.getChildrenCondition() != null) {
			Collection children = original.getChildrenCondition();
			Collection childrenNous = new ArrayList();
			if (children != null)
				for (Iterator<PolicyCondition> it = children.iterator(); it.hasNext();) {
					PolicyCondition f = it.next();
					childrenNous.add(clonaPC(f));
				}
			pc.setChildrenCondition(childrenNous);
		}
		return pc;
	}

	public static AttributePolicyCondition clonaAC(AttributePolicyCondition original) {
		AttributePolicyCondition pc = new AttributePolicyCondition(original);
		if (original.getAttribute() != null)
			pc.setAttribute(new Attribute(original.getAttribute()));
		if (original.getChildrenCondition() != null) {
			Collection children = original.getChildrenCondition();
			Collection childrenNous = new ArrayList();
			if (children != null)
				for (Iterator<AttributePolicyCondition> it = children.iterator(); it.hasNext();) {
					AttributePolicyCondition f = it.next();
					childrenNous.add(clonaAC(f));
				}
			pc.setChildrenCondition(childrenNous);
		}
		return pc;
	}
}