package com.soffid.iam.addons.federation.web;

import java.util.LinkedList;
import java.util.List;

import javax.naming.InitialContext;

import org.json.JSONArray;
import org.json.JSONObject;
import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.UiException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Div;

import com.soffid.iam.addons.federation.common.UserConsent;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;

import es.caib.zkib.component.DataTable;
import es.caib.zkib.zkiblaf.Missatgebox;

public class ConsentsTab extends Div implements AfterCompose {
	private static final long serialVersionUID = 1L;
	private List<UserConsent> consents;
	private FederationService svc;

	public void afterCompose() {
		try {
			DataTable dt = (DataTable) getFellow("consentsTable");
			JSONArray a = new JSONArray();
			svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
			consents = new LinkedList<UserConsent>( svc.findUserConsents() );
			for (UserConsent c: consents) {
				JSONObject o = new JSONObject();
				o.put("name", c.getServiceProvider());
				o.put("date", c.getDate());
				o.put("date_datetime", es.caib.zkib.component.DateFormats.getDateTimeFormat().format(c.getDate()));
				a.put(o);
			}
			dt.setData(a);
		} catch (Exception e) {
			throw new UiException(e);
		}
	}

	public void removeConsent(Event event) {
		final DataTable dt = (DataTable) getFellow("consentsTable");
		final int i = dt.getSelectedIndex();
		if (i >= 0) {
			Missatgebox.confirmaOK_CANCEL(Labels.getLabel("common.delete"), 
					(event2) -> {
						if (event2.getName().equals("onOK")) {
							UserConsent uc = consents.get(i);
							svc.deleteUserConsent(uc);
							dt.delete();
						}
					});
		}
	}
}
