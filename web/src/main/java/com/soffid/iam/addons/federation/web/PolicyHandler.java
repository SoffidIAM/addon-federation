package com.soffid.iam.addons.federation.web;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

import org.json.JSONException;
import org.zkoss.zk.ui.Page;
import org.zkoss.zk.ui.UiException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zul.Textbox;
import org.zkoss.zul.Treechildren;
import org.zkoss.zul.Treeitem;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.AttributePolicyCondition;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.Policy;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataModel;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.datasource.CommitException;
import es.caib.zkib.datasource.XPathUtils;

public class PolicyHandler extends FrameHandler {
	private boolean isMaster;
	private boolean canCreateParameter;
	private boolean canUpdateParameter;
	private boolean canDeleteParameter;
	private boolean canQueryParameter;
	private Policy currentPolicy;
	private LinkedList<Attribute> attributes;

	public PolicyHandler() throws InternalErrorException {
	}

	@Override
	public void setPage(Page p) {
		super.setPage(p);
		getNamespace().setVariable("isMaster", isMaster, true);
		getNamespace().setVariable("canCreateParameter", canCreateParameter, true);
		getNamespace().setVariable("canUpdateParameter", canUpdateParameter, true);
		getNamespace().setVariable("canDeleteParameter", canDeleteParameter, true);
		getNamespace().setVariable("canQueryParameter", canQueryParameter, true);
	}
		

	public void onChangeDades() {
		Policy p = null;
		try {
			p = (Policy) XPathUtils.eval(getListbox(), "instance");
		} catch (Exception e) {}
		try {
			String desc = "";
			if (p != null && p.getCondition() != null) {
				desc = ExpressionHelper.getLongDescription(p.getCondition());
				Textbox cf = (Textbox) getFellow("condition");
				cf.setValue(desc);
			}
		} catch (Exception e) {
			throw new UiException(e);
		}
	}
	
	public void addAttribute(Event event) throws Exception {
		AttributePolicy ap = new AttributePolicy();
		ap.setAttribute(new Attribute());
		afegirAtribut(ap, false);
	}

	public boolean comprovaAtributAmbValor (com.soffid.iam.addons.federation.common.Attribute a) {
		
		boolean valor = false;
		if (a!=null) {
			if (a.getName()!=null) {
				if (!"".equals(a.getName().trim())) valor = true;	
			}
			if (!valor && a.getShortName()!=null) {
				if (!"".equals(a.getShortName().trim())) valor = true;
			}
			if (!valor && a.getOid() !=null) {
				if (!"".equals(a.getOid().trim())) valor = true;
			}
				
		}
	
		return valor;
	}
	
	
	void afegirAtribut(AttributePolicy attPolicy, boolean principal) throws Exception {
		if (attPolicy == null) {
			return;
		}
		// Mirem si en té condició, sinó es genera una
		AttributePolicyCondition princCond = attPolicy.getAttributePolicyCondition();
		if (princCond == null) { //generem una genèrica (ANY)
			princCond = new AttributePolicyCondition(com.soffid.iam.addons.federation.common.ConditionType.ANY, "", true);
			attPolicy.setAttributePolicyCondition(princCond);
		}

	}
	
	@Override
	public void afterCompose() {
		attributes = new LinkedList<Attribute>();
		super.afterCompose();
		DataModel model = (DataModel) getFellow("model");
		for (Iterator it = model.getJXPathContext().iterate("/atribut/instance"); it.hasNext(); ) {
			attributes.add((Attribute) it.next());
		}
	}
	
	public void openCondition(Event ev) throws JSONException, IOException, CommitException {
		if (applyNoClose(ev)) {
			Window w = (Window) getFellow("conditionWindow");
			w.doHighlighted();
			ExpressionEditor ed = (ExpressionEditor) w.getFellow("handler");
			ed.updateTree();
		}
	}
	
	public void selectAttribute(Event ev) throws JSONException, CommitException, IOException {
		if (applyNoClose(ev)) {
			Window w = (Window) getFellow("attributeWindow");
			w.doHighlighted();
			ExpressionEditor ed = (ExpressionEditor) w.getFellow("handler");
			ed.updateTree();
		}		
	}
	
	public void addNewAttribute(Event ev) throws Exception {
		applyNoClose(ev);
		DataTable dt = (DataTable) getFellow("listbox");
		final AttributePolicy att = new AttributePolicy();
//		att.setAttribute(attributes.getFirst());
		att.getAttributePolicyCondition().setType(ConditionType.ANY);
		XPathUtils.createPath(dt, "/attributePolicy", att);
		DataTable dt2 = (DataTable) getFellow("attributesListbox");
		dt2.setSelectedIndex(dt2.getModel().getSize()-1);
		selectAttribute(ev);
	}

	@Override
	public void addNew() throws Exception {
		super.addNew();
		PolicyCondition c = new PolicyCondition();
		c.setType(ConditionType.ANY);
		XPathUtils.setValue(getForm(), "condition", c);
	}
}
