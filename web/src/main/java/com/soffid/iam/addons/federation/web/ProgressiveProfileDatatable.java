package com.soffid.iam.addons.federation.web;

import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.SAMLProfile;

import es.caib.zkib.component.DataTable;
import es.caib.zkib.datamodel.DataNode;


public class ProgressiveProfileDatatable extends DataTable {
	static String[] defaultColumns = {
			"order", "name", "fields"
	};
	
	public ProgressiveProfileDatatable() throws Exception {
	}
	

}
