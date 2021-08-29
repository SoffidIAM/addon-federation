package com.soffid.iam.addons.federation.web;

import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.SAMLProfile;

import es.caib.zkib.component.DataTable;
import es.caib.zkib.datamodel.DataNode;


public class ProfileDatatable extends DataTable {
	static String[] defaultColumns = {
			"userName", "fullName", "primaryGroup", "active"
	};
	
	public ProfileDatatable() throws Exception {
	}
	
	@Override
	protected JSONObject getClientValue(Object element) throws JSONException {
		JSONObject s = super.getClientValue(element);
		SAMLProfile u = (SAMLProfile) ((DataNode)element).getInstance();
		if (Boolean.FALSE.equals(u.getEnabled()))
			s.put("$class", "dashed");
		else
			s.put("$class", "std");
		return s;
	}

}
