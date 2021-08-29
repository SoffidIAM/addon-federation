package com.soffid.iam.addons.federation.web;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.bouncycastle.util.Arrays;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Page;
import org.zkoss.zk.ui.UiException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.AttributePolicy;
import com.soffid.iam.addons.federation.common.ConditionType;
import com.soffid.iam.addons.federation.common.PolicyCondition;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.web.component.CustomField3;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.binder.BindContext;
import es.caib.zkib.binder.SingletonBinder;
import es.caib.zkib.component.DataModel;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.component.DataTree2;
import es.caib.zkib.component.Div;
import es.caib.zkib.datamodel.DataNode;
import es.caib.zkib.datasource.CommitException;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.events.XPathEvent;
import es.caib.zkib.events.XPathRerunEvent;
import es.caib.zkib.events.XPathSubscriber;

public class ExpressionEditor extends Div implements XPathSubscriber, AfterCompose { 
	SingletonBinder binder = new SingletonBinder(this);
	private PolicyCondition activeCondition;
	private CustomField3 attributeValue;
	private String activePath;
	private CustomField3 type;
	private CustomField3 not;
	private CustomField3 attributeNameFormat;
	private CustomField3 groupId;
	private CustomField3 nameId;
	private CustomField3 ignoreCase;
	private CustomField3 regex;
	private CustomField3 value;
	private CustomField3 attribute;
	private boolean duringUpdate = false;
	private PolicyCondition parentExpression = null;
	private AttributePolicy rootAttributePolicy;
	private PolicyCondition rootPolicyCondition;
	private Collection<Attribute> allAttributes;
	
	public void setDataPath(String path) {
		binder.setDataPath(path);
	}

	@Override
	public void onPageAttached(Page newpage, Page oldpage) {
		super.onPageAttached(newpage, oldpage);
		binder.setPage(newpage);
	}

	@Override
	public void onPageDetached(Page page) {
		super.onPageDetached(page);
		binder.setPage(null);
	}

	@Override
	public void onUpdate(XPathEvent event) {
		try {
			if (!duringUpdate)
				updateTree();
		} catch (JSONException | IOException e) {
			throw new UiException(e);
		}
	}

	@Override
	public Object clone() {
		ExpressionEditor o = (ExpressionEditor) super.clone();
		o.binder = new SingletonBinder(o);
		return o;
	}

	@Override
	public void afterCompose() {
		try {
			type = (CustomField3) getFellow("type");
			not = (CustomField3) getFellow("not");
			attribute = (CustomField3) getFellow("attribute");
			attributeNameFormat = (CustomField3) getFellow("attributeNameFormat");
			groupId = (CustomField3) getFellow("groupId");
			nameId = (CustomField3) getFellow("nameId");
			ignoreCase = (CustomField3) getFellow("ignoreCase");
			regex = (CustomField3) getFellow("regex");
			value = (CustomField3) getFellow("value");
			FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			allAttributes = svc.findAtributs(null, null, null);
			updateTree();
		} catch (Exception e) {
			throw new UiException(e);
		}
	}

	public void updateTree() throws JSONException, IOException {
		DataTree2 dt = (DataTree2) getFellow("dt");
		JSONObject data = new JSONObject();
		JSONArray children = new JSONArray();
		data.put("children", children);
		if (binder.isValid()) {
			Object o = binder.getValue();
			if (o == null) {
				rootPolicyCondition = null;
				activeCondition = null;
				rootAttributePolicy = null;
			}
			else if (o instanceof PolicyCondition) {
				rootPolicyCondition = (PolicyCondition) o;
				activeCondition = rootPolicyCondition;
				rootAttributePolicy = null;
			} else {
				rootAttributePolicy = (AttributePolicy) o;
				activeCondition = rootAttributePolicy.getAttributePolicyCondition();
				rootPolicyCondition = null;
			}
			children.put (render(activeCondition));
			parentExpression  = null;
			dt.setData(data);
			dt.setSelectedIndex(new int[] {0});
		} else {
			dt.setData(data);
			rootAttributePolicy = null;
			rootPolicyCondition = null;
			activeCondition = null;
			parentExpression = null;
		}
		updateForm();
	}

	
	private JSONObject render(PolicyCondition e) throws JSONException, IOException {
		String description = ExpressionHelper.getShortDescription(e);
		int minChildren = ExpressionHelper.getMinChildren(e);
		int maxChildren = ExpressionHelper.getMaxChildren(e);
		
		JSONObject o = new JSONObject();
		o.put("type", "condition");
		o.put("value", description);
		if (maxChildren == 0) {
			o.put("leaf", true);
			o.put("children", new JSONArray());
		} else {
			if (e.getChildrenCondition() == null)
				e.setChildrenCondition( new LinkedList<>() );
			JSONArray children = new JSONArray();
			o.put("children", children);
			Iterator<PolicyCondition> it = e.getChildrenCondition().iterator();
			for (int i = 0; i < minChildren || i < e.getChildrenCondition().size(); i++) {
				PolicyCondition s;
				if ( i >= e.getChildrenCondition().size()) {
					s = newCondition(e);
				} else {
					s = it.next();
				}
				children.put(render(s));
			}
			if (e.getChildrenCondition().size() < maxChildren || maxChildren == -1) {
				o.put("tail", "<button class=\"small-button\" onclick=\"zkDatatree2.sendClientAction(this, 'onAddExpression')\">"+
						Labels.getLabel("federacio.zul.addNew")+
						"</button>");
			}
		}
		return o;
	}

	public void onSelect(Event event) throws JSONException, IOException {
		DataTree2 dt = (DataTree2) event.getTarget();
		int selected[] = dt.getSelectedItem();
		
		
		PolicyCondition e = rootAttributePolicy != null ? rootAttributePolicy.getAttributePolicyCondition() : rootPolicyCondition;
		PolicyCondition p = null;
		Collection<PolicyCondition> l = new LinkedList<PolicyCondition>();
		l.add(e);
		
		String path = "";
		for (int i = 1; i < selected.length; i++) {
			path = path + "/subexpression["+selected[i]+"]";
		}
		activePath = path;
		
		e = null;
		for (int i = 0; i < selected.length; i++) {
			if (l == null)
				return;
			Iterator<PolicyCondition> iterator = l.iterator();
			for (int j = 0; j < selected[i]; j++) {
				if (iterator.hasNext()) iterator.next();
			}
			if (iterator.hasNext()) {
				p = e;
				e = iterator.next();
				l = e.getChildrenCondition();
			} else {
				return;
			}
		}
		
		parentExpression = p;
		activeCondition = e;
		
		updateForm();
	}
	
	public void addExpression(Event event) throws JSONException, IOException {
		DataTree2 dt = (DataTree2) getFellow("dt");

		PolicyCondition e = newCondition(activeCondition);
		refreshActiveTree();
		int size = activeCondition.getChildrenCondition().size();
		int[] item = dt.getSelectedItem();
		int[] newItem = Arrays.copyOf(item, item.length+1);
		newItem[item.length] = size - 1;
		dt.setSelectedIndex(newItem);
		
		parentExpression = activeCondition;
		activeCondition = e;
		
		updateForm();
	}
	
	public void removeExpression (Event event) throws JSONException, IOException {
		DataTree2 dt = (DataTree2) getFellow("dt");

		int[] item = dt.getSelectedItem();
		
		parentExpression.getChildrenCondition().remove(activeCondition);
		int[] newItem = Arrays.copyOf(item, item.length-1);
		
		dt.setSelectedIndex(newItem);
		JSONObject data = render(parentExpression);
		dt.updateCurrentBranch(data);

		if ( item [item.length-1] >= parentExpression.getChildrenCondition().size()) {
			item [item.length-1] --;
		}
		
		Iterator<PolicyCondition> it = parentExpression.getChildrenCondition().iterator();
		for (int i = 0; i <= item[item.length-1]; i++) {
			activeCondition = it.next();
		}
		dt.setSelectedIndex(item);
		
		updateForm();
	}

	public void updateNot(Event event) throws JSONException, IOException {
		activeCondition.setNegativeCondition((Boolean) not.getValue());
		refreshActiveTree();
	}

	public void updateIgnoreCase(Event event) throws JSONException, IOException {
		activeCondition.setIgnoreCase((Boolean) ignoreCase.getValue());
		refreshActiveTree();
	}

	public void updateType(Event event) throws JSONException, IOException {
		activeCondition.setType((ConditionType) type.getValue());
		updateForm();
		refreshActiveTree();
	}
	
	public void updateAttributeNameFormat(Event event) throws JSONException, IOException {
		activeCondition.setAttributeNameFormat((String) attributeNameFormat.getValue());
		refreshActiveTree();
	}

	public void updateGroupId(Event event) throws JSONException, IOException {
		activeCondition.setGroupId((String) groupId.getValue());
		refreshActiveTree();
	}
	
	public void updateNameId(Event event) throws JSONException, IOException {
		activeCondition.setNameId((String) nameId.getValue());
		refreshActiveTree();
	}
	
	public void updateAttribute(Event event) throws JSONException, IOException {
		String attName = (String) attribute.getValue();
		for ( Attribute a: allAttributes) {
			if (a.getName().equals(attName))
				activeCondition.setAttribute(a);
		}
		refreshActiveTree();
	}
	
	public void updateValue(Event event) throws JSONException, IOException {
		activeCondition.setValue((String) value.getValue());
		refreshActiveTree();
	}

	public void updateRegex(Event event) throws JSONException, IOException {
		activeCondition.setRegex((String) regex.getValue());
		try {
			Pattern.compile(activeCondition.getRegex());
		} catch (PatternSyntaxException e) {
			regex.setWarning(0, e.getMessage());
		}
		refreshActiveTree();
	}

	public void updateForm() throws JSONException, IOException {
		type.setVisible(false);
		attribute.setVisible(false);
		attributeNameFormat.setVisible(false);
		groupId.setVisible(false);
		nameId.setVisible(false);
		ignoreCase.setVisible(false);
		regex.setVisible(false);
		value.setVisible(false);

		Component removeIcon = getFellow("removeIcon");
		
		if (activeCondition != null) {
			ConditionType t = activeCondition.getType();
			type.setValue(t);
			type.setVisible(true);
			not.setValue( Boolean.TRUE.equals( activeCondition.getNegativeCondition()));
			attribute.setValue(activeCondition.getAttribute() == null ? null: activeCondition.getAttribute().getName());
			attributeNameFormat.setValue(activeCondition.getAttributeNameFormat());
			groupId.setValue(activeCondition.getGroupId());
			nameId.setValue(activeCondition.getNameId());
			ignoreCase.setValue(activeCondition.getIgnoreCase());
			regex.setValue(activeCondition.getRegex());
			value.setValue(activeCondition.getValue());
			if (t == ConditionType.AND || t == ConditionType.ANY || t == ConditionType.OR) {
				// Nothing to show
			}
			else if (t == ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_EXACT_MATCH || 
					t == ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_EXACT_MATCH) {
				nameId.setVisible(true);
				attributeNameFormat.setVisible(true);
				value.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_ISSUER_ENTITY_ATTRIBUTE_REGEX_MATCH || 
					t == ConditionType.ATTRIBUTE_REQUESTER_ENTITY_ATTRIBUTE_REGEX_MATCH) {
				nameId.setVisible(true);
				attributeNameFormat.setVisible(true);
				regex.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_ISSUER_IN_ENTITY_GROUP || 
					t == ConditionType.ATTRIBUTE_REQUESTER_IN_ENTITY_GROUP) {
				groupId.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_ISSUER_NAME_IDFORMAT_EXACT_MATCH || 
					t == ConditionType.ATTRIBUTE_REQUESTER_NAME_IDFORMAT_EXACT_MATCH) {
				attributeNameFormat.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_ISSUER_REGEX || 
					t == ConditionType.ATTRIBUTE_REQUESTER_REGEX||
					t == ConditionType.AUTHENTICATION_METHOD_REGEX) {
				regex.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_ISSUER_STRING || 
					t == ConditionType.ATTRIBUTE_REQUESTER_STRING ||
					t == ConditionType.AUTHENTICATION_METHOD_STRING) {
				value.setVisible(true);
				ignoreCase.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_VALUE_REGEX ) {
				regex.setVisible(true);
				attribute.setVisible(true);
			}
			else if (t == ConditionType.ATTRIBUTE_VALUE_STRING) {
				value.setVisible(true);
				ignoreCase.setVisible(true);
				attribute.setVisible(true);
			}
			
			if (parentExpression == null)
				removeIcon.setVisible(false);
			else
			{
				int min = ExpressionHelper.getMinChildren(parentExpression);
				if (parentExpression.getChildrenCondition().size() > min) 
					removeIcon.setVisible(true);
				else
					removeIcon.setVisible(false);
			}
		} else {
			removeIcon.setVisible(false);
		}
	}

	void refreshActiveTree() throws JSONException, IOException {
		JSONObject data = render(activeCondition);
		
		DataTree2 dt = (DataTree2) getFellow("dt");
		dt.updateCurrentBranch(data);
		
		duringUpdate = true;
		try {
			binder.getDataSource().sendEvent(new XPathRerunEvent(binder.getDataSource(), binder.getDataPath()));
			final Component listbox = getPage().getFellow("listbox");
			DataNode policyNode = (DataNode) XPathUtils.eval(listbox,  "/");
			policyNode.update();
			if (rootAttributePolicy != null) {
				getPage().getFellow("attributesListbox").invalidate();
			}
		} finally {
			duringUpdate  = false;
		}
	}
	

	private PolicyCondition newCondition(PolicyCondition parent) {
		PolicyCondition policyCondition = new PolicyCondition();
		policyCondition.setType(ConditionType.ANY);
		if (parent != null) {
			parent.getChildrenCondition().add(policyCondition);
		}
		return policyCondition;
	}
	
	public void apply(Event ev) throws CommitException {
		Window w = (Window) getParent();
		PolicyHandler frame = (PolicyHandler) w.getParent().getFellow("frame");
		if (frame.validateAttributes(w) && frame.applyNoClose(ev)) {
			w.setVisible(false);
			DataTable dt = (DataTable) frame.getFellow("attributesListbox");
			dt.setSelectedIndex(-1);
			frame.onChangeDades();
		}
	}
	
	public void changeAttribute(Event event) throws JSONException, IOException {
		String name = (String) ((CustomField3)event.getTarget()).getValue();
		DataTable listbox = (DataTable) getPage().getFellow("attributesListbox");
		for ( Attribute a: allAttributes) {
			if (a.getName().equals(name))
				XPathUtils.setValue(listbox, "/attribute", new Attribute(a));
		}
		listbox.updateClientRow(listbox.getSelectedIndex());
	}

}
