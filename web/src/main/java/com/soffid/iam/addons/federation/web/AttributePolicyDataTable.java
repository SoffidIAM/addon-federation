package com.soffid.iam.addons.federation.web;

import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.AttributePolicy;

import es.caib.zkib.component.DataTable;

public class AttributePolicyDataTable extends DataTable {

	@Override
	protected JSONObject getClientValue(Object element) throws JSONException {
		JSONObject o = super.getClientValue(element);
		AttributePolicy a = (AttributePolicy) element;
		String desc = ExpressionHelper.getLongDescription(a.getAttributePolicyCondition());
		o.put("expression", desc);
		return o;
	}

}
