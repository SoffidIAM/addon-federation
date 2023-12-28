package com.soffid.iam.addons.federation.web;

import java.net.URLEncoder;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

import javax.naming.InitialContext;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.System;
import com.soffid.iam.web.component.InputField3;
import com.soffid.iam.web.component.InputFieldUIHandler;

import es.caib.zkib.component.Databox.Type;

public class OauthFieldHandler extends InputFieldUIHandler {
	@Override
	public boolean isVisible(InputField3 field) throws Exception {
		return true;
	}

	@Override
	public void afterCreate(InputField3 field) throws Exception {
		field.setType(Type.LIST);
		FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
		LinkedList<Attribute> all = new LinkedList<>(svc.findAtributs(null, null, null));
		Collections.sort(all, new Comparator<Attribute>() {
			@Override
			public int compare(Attribute o1, Attribute o2) {
				if (o1.getName() == null && o2.getName() != null)
					return -1;
				if (o1.getName() != null && o2.getName() == null)
					return +1;
				return o1.getName().compareToIgnoreCase(o2.getName());
			}
		});
		List<String> values = new LinkedList<>();
		for (Attribute s: all) {
			if (s.getOpenidName() != null && !s.getOpenidName().trim().isEmpty())
				values.add( URLEncoder.encode(s.getOpenidName(), "UTF-8")+":"+s.getName());
		}
		field.setValues(values);
	}

}
