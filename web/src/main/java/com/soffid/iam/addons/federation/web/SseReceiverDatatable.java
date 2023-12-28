package com.soffid.iam.addons.federation.web;

import java.util.Collection;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.api.DataType;
import com.soffid.iam.web.component.DatatypeColumnsDatatable;

public class SseReceiverDatatable extends DatatypeColumnsDatatable {

	@Override
	public Collection<DataType> getDataTypes() throws Exception {
		return new EJBLocator().getAdditionalDataService().findDataTypesByObjectTypeAndName2(SseReceiver.class.getName(), null);
	}

	@Override
	public String[] getDefaultColumns() throws Exception {
		return new String[] {"name", "description"};
	}

}
