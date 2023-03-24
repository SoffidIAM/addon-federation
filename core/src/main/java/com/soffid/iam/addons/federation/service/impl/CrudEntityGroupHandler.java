package com.soffid.iam.addons.federation.service.impl;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import com.soffid.iam.EJBLocator;
import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.api.AsyncList;
import com.soffid.iam.api.CrudHandler;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.service.ejb.UserService;

public class CrudEntityGroupHandler implements CrudHandler<EntityGroup> {
	private FederationService ejb;

	public FederationService getService() throws NamingException, CreateException {
		if (ejb == null)
			ejb = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
		return ejb;
	}
	

	
	@Override
	public EntityGroup create(EntityGroup object) throws Exception {
		return ejb.create(object);
	}

	@Override
	public PagedResult<EntityGroup> read(String text, String filter, Integer start, Integer maxobjects)
			throws Exception {
		return getService().findEntityGroupsByJsonQuery(text, filter, start, maxobjects);
	}

	@Override
	public AsyncList<EntityGroup> readAsync(String text, String filter) throws Exception {
		return getService().findEntityGroupsByJsonQueryAsync(text, filter);
	}

	@Override
	public EntityGroup update(EntityGroup object) throws Exception {
		return getService().update(object);
	}

	@Override
	public void delete(EntityGroup object) throws Exception {
		getService().delete(object);
	}

}
