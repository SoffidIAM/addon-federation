//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import org.springframework.transaction.annotation.Transactional;

import com.soffid.iam.addons.federation.api.HostCredential;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.HostCredentialEntity;
import com.soffid.iam.addons.federation.roles.federation_credential_query;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Operation;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.model.ConfiguracioEntity;
import es.caib.seycon.ng.model.MaquinaEntity;
import es.caib.seycon.ng.model.UsuariEntity;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.servei.XarxaService;
import roles.federation_create_push;
import roles.federation_create_token;
import roles.hostcertificate_query;
import roles.hostcertificate_remove;
import roles.selfcertificate_user;

@Service(serverPath = "/seycon/HostCredentialService", serverRole="agent")
@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	HostCredentialEntity.class,
	ConfiguracioEntity.class,
	UsuariService.class,
	XarxaService.class,
	FederationMemberEntity.class,
	MaquinaEntity.class,
	UsuariEntity.class})
public class HostCredentialService 
{
	@Operation ( grantees={hostcertificate_query.class})
	public java.util.List<HostCredential> findHostCredentials( String user ) 
		{ return null; }

	@Operation ( grantees={hostcertificate_remove.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void remove(HostCredential credential)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	
	public HostCredential updateLastUse (HostCredential uc) {return null;}

	public String generateNextSerial() {return null;}

}
