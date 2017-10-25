package com.soffid.iam.addons.federation.remote;

import java.io.IOException;

import com.soffid.iam.addons.federation.service.FederacioService;

import es.caib.seycon.ng.exception.InternalErrorException;


public class RemoteServiceLocator extends com.soffid.iam.remote.RemoteServiceLocator {
	public FederacioService getFederacioService () throws IOException, InternalErrorException 
	{
		return (FederacioService) getRemoteService(FederacioService.REMOTE_PATH);
	}

}
