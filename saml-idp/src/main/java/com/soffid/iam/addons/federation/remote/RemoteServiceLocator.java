package com.soffid.iam.addons.federation.remote;

import java.io.IOException;

import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.addons.federation.service.UserBehaviorService;

import es.caib.seycon.ng.exception.InternalErrorException;


public class RemoteServiceLocator extends com.soffid.iam.remote.RemoteServiceLocator {
	public FederationService getFederacioService () throws IOException, InternalErrorException 
	{
		return (FederationService) getRemoteService(FederationService.REMOTE_PATH);
	}

	public UserBehaviorService getUserBehaviorService () throws IOException, InternalErrorException 
	{
		return (UserBehaviorService) getRemoteService(UserBehaviorService.REMOTE_PATH);
	}

}
