package com.soffid.iam.addons.federation.service.impl;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.CrudHandler;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.service.ejb.UserService;

public class CrudFederationMemberHandler implements CrudHandler<FederationMember> {
	private FederationService ejb;

	public FederationService getService() throws NamingException, CreateException {
		if (ejb == null)
			ejb = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
		return ejb;
	}
	

	
	@Override
	public FederationMember create(FederationMember object) throws Exception {
		return getService().create(object);
	}

	@Override
	public PagedResult<FederationMember> read(String text, String filter, Integer start, Integer maxobjects)
			throws Exception {
		return getService().findFederationMembersByJsonQuery(text, filter, start, maxobjects);
	}

	@Override
	public AsyncList<FederationMember> readAsync(String text, String filter) throws Exception {
		return getService().findFederationMembersByJsonQueryAsync(text, filter);
	}

	@Override
	public FederationMember update(FederationMember object) throws Exception {
		return getService().update(object);
	}

	@Override
	public void delete(FederationMember object) throws Exception {
		getService().delete(object);
	}

}
