package com.soffid.iam.federation.idp;

import java.io.IOException;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.service.EssoService;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.addons.federation.service.PushAuthenticationService;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.addons.federation.service.UserCredentialService;
import com.soffid.iam.service.SessionService;

import es.caib.seycon.ng.config.Config;
import es.caib.seycon.ng.exception.InternalErrorException;


public class RemoteServiceLocator extends com.soffid.iam.remote.RemoteServiceLocator {
	public FederationService getFederacioService () throws IOException, InternalErrorException 
	{
		if ("server".equals(Config.getConfig().getRole()))
			return (FederationService) ServiceLocator.instance().getService(FederationService.SERVICE_NAME);
		else
			return (FederationService) getRemoteService(FederationService.REMOTE_PATH);
	}

	public UserBehaviorService getUserBehaviorService () throws IOException, InternalErrorException 
	{
		if ("server".equals(Config.getConfig().getRole()))
			return (UserBehaviorService) ServiceLocator.instance().getService(UserBehaviorService.SERVICE_NAME);
		else
			return (UserBehaviorService) getRemoteService(UserBehaviorService.REMOTE_PATH);
	}

	public UserCredentialService getUserCredentialService () throws IOException, InternalErrorException 
	{
		if ("server".equals(Config.getConfig().getRole()))
			return (UserCredentialService) ServiceLocator.instance().getService(UserCredentialService.SERVICE_NAME);
		else
			return (UserCredentialService) getRemoteService(UserCredentialService.REMOTE_PATH);
	}

	public PushAuthenticationService getPushAuthenticationService () throws IOException, InternalErrorException 
	{
		if ("server".equals(Config.getConfig().getRole()))
			return (PushAuthenticationService) ServiceLocator.instance().getService(PushAuthenticationService.SERVICE_NAME);
		else
			return (PushAuthenticationService) getRemoteService(PushAuthenticationService.REMOTE_PATH);
	}

	public SharedSignalEventsService getSharedSignalEventsService () throws IOException, InternalErrorException 
	{
		if ("server".equals(Config.getConfig().getRole()))
			return (SharedSignalEventsService) ServiceLocator.instance().getService(SharedSignalEventsService.SERVICE_NAME);
		else
			return (SharedSignalEventsService) getRemoteService(SharedSignalEventsService.REMOTE_PATH);
	}

	public EssoService getEssoService() throws IOException, InternalErrorException {
		if ("server".equals(Config.getConfig().getRole()))
			return (EssoService) ServiceLocator.instance().getService(EssoService.SERVICE_NAME);
		else
			return (EssoService) getRemoteService(EssoService.REMOTE_PATH);
	}
}
