package com.soffid.iam.addons.federation.web;

import java.util.Iterator;

import org.zkoss.zk.ui.Component;
import org.zkoss.zul.Listbox;
import org.zkoss.zul.Listitem;
import org.zkoss.zul.Row;
import org.zkoss.zul.Textbox;

import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import es.caib.zkib.zkiblaf.ImageClic;

/**
 * Classe gràfica per implementar elements de Federació d'identitats.
 * 
 * by Alejandro Usero Ruiz - 09/05/2012
 * 
 * @author u88683
 * 
 */
public class FederationElementFill implements java.io.Serializable {

	private static final long serialVersionUID = 1L;

	private Component contenidor; // Contenedor gráfico de filas
	private Row filera;
	private ImageClic botoEsborrar;
	private ImageClic botoAfegir;
	private Listbox lb_tipusCondicio;
	private Textbox tb_value;

	public FederationElementFill(Component contenidor, PolicyCondition condicio, boolean principal) {
		this.contenidor = contenidor;
		this.filera = new Row();
		filera.setStyle("background-color: white;"); //$NON-NLS-1$

		this.lb_tipusCondicio = new Listbox();
		lb_tipusCondicio.setMold("select"); //$NON-NLS-1$

		Listitem condicioSeleccionada = null;

		for (Iterator it = ConditionType.literals().iterator(); it.hasNext();) {
			String name = (String) it.next();
			ConditionType c = ConditionType.fromString(name); // condició actual
			Listitem l = new Listitem(name, c);
			lb_tipusCondicio.appendChild(l);
			if (c.equals(condicio.getType())) {
				// seleccionem el q toca
				condicioSeleccionada = l;
			}

		}
		filera.appendChild(lb_tipusCondicio);
		lb_tipusCondicio.setWidth("99%"); //$NON-NLS-1$
		lb_tipusCondicio.setSelectedItem(condicioSeleccionada);

		// Camp de texto
		tb_value = new Textbox(condicio.getValue());
		tb_value.setSclass("textbox"); //$NON-NLS-1$
		filera.appendChild(tb_value);
		tb_value.setWidth("99%"); //$NON-NLS-1$

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

		filera.appendChild(botoAfegir);
		filera.appendChild(botoEsborrar);

		comprovaCondicio(condicio.getType());

		// Lo insertamos gráficamente
		contenidor.insertBefore(filera, null);
	}

	public Row getFila() {
		return filera;
	}

	// public void setTextoCampo(String texto, int campo) {
	// tb[campo].setValue(texto);
	// }

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

	protected void comprovaCondicio(ConditionType tipus) {
		tb_value.setDisabled(ConditionType.ANY.equals(tipus) || ConditionType.OR.equals(tipus) || ConditionType.AND.equals(tipus));
		botoAfegir.setVisible(ConditionType.ANY.equals(tipus) || ConditionType.OR.equals(tipus) || ConditionType.AND.equals(tipus));
	}

}