package com.soffid.iam.addons.federation.web;

import java.net.URI;

import javax.naming.InitialContext;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.Path;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.service.ejb.UserCredentialService;
import com.soffid.iam.addons.federation.service.ejb.UserCredentialServiceHome;
import com.soffid.iam.web.component.FrameHandler;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataModel;
import es.caib.zkib.component.DataTable;
import es.caib.zkib.datamodel.DataModelCollection;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.zkiblaf.Missatgebox;

public class UserTokenHandler extends FrameHandler {
	public UserTokenHandler() throws InternalErrorException {
		super();
	}
	String parentPath;
	String model;

	@Override
	public void addNew() throws Exception {
		UserCredentialService ejb = (UserCredentialService) new InitialContext().lookup(UserCredentialServiceHome.JNDI_NAME);
		
		String user = (String) XPathUtils.eval(getParentListbox(), "/userName");
		URI uri = ejb.generateNewCredential(user);
		
		Missatgebox.avis(Labels.getLabel("federation.token.urlmessage")+"\n\n"+ uri.toString());
	}

	public void refresh() throws Exception {
		DataModelCollection coll = (DataModelCollection) XPathUtils.eval(getParentListbox(), "/token");
		DataTable dt = (DataTable) getListbox();
		if (dt.getSelectedIndexes().length == 0)
			coll.refresh();
	}

	public String getParentPath() {
		return parentPath;
	}

	public void setParentPath(String parentPath) {
		this.parentPath = parentPath;
	}

	@Override
	protected DataModel getModel() {
		return (DataModel) Path.getComponent(getPage(), model);
	}

	public void setModel(String model) {
		this.model = model;
	}
	
	public DataTable getParentListbox() {
		return (DataTable) Path.getComponent(getPage(), parentPath);
	}
	
}
