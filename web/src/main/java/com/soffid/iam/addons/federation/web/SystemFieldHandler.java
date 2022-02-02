package com.soffid.iam.addons.federation.web;

import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.api.System;
import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.InputFieldUIHandler;

import es.caib.zkib.component.Databox.Type;

public class SystemFieldHandler extends InputFieldUIHandler {
	@Override
	public boolean isVisible(InputField3 field) throws Exception {
		return true;
	}

	@Override
	public void afterCreate(InputField3 field) throws Exception {
		field.setType(Type.LIST);
		LinkedList<System> all = new LinkedList<>( EJBLocator.getDispatcherService().findSystemByTextAndFilter("", "", null, null).getResources() );
		Collections.sort(all, new Comparator<System>() {
			@Override
			public int compare(System o1, System o2) {
				if (o1.getUrl() == null && o2.getUrl() != null)
					return -1;
				if (o1.getUrl() != null && o2.getUrl() == null)
					return +1;
				return o1.getName().compareToIgnoreCase(o2.getName());
			}
		});
		List<String> values = new LinkedList<>();
		for (System s: all)
			values.add(s.getName()+":"+s.getName()+" - "+s.getDescription());
		field.setValues(values);
	}

}
