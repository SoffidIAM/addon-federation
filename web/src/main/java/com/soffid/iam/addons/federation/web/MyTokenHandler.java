package com.soffid.iam.addons.federation.web;

import java.net.URI;

import javax.naming.InitialContext;

import org.zkoss.zk.ui.Executions;

import com.soffid.iam.addons.federation.service.ejb.UserCredentialService;
import com.soffid.iam.addons.federation.service.ejb.UserCredentialServiceHome;
import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.datamodel.DataModelCollection;
import es.caib.zkib.datasource.XPathUtils;

public class MyTokenHandler extends FrameHandler {
	public MyTokenHandler() throws InternalErrorException {
		super();
	}

	
	public void refresh() {
		DataTable dt = (DataTable) getListbox();
		if (dt.getSelectedIndexes().length == 0)
			getModel().refresh();
	}
	
	@Override
	public void addNew() throws Exception {
		UserCredentialService ejb = (UserCredentialService) new InitialContext().lookup(UserCredentialServiceHome.JNDI_NAME);
		
		URI uri = ejb.generateNewCredential();
		
		Executions.getCurrent().sendRedirect(uri.toString(), "_blank");
	}

}
