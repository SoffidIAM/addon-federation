//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.UserCredentialChallengeEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.addons.federation.model.UserCredentialRequestEntity;
import com.soffid.iam.addons.federation.roles.federation_credential_create;
import com.soffid.iam.addons.federation.roles.federation_credential_query;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.model.ConfiguracioEntity;
import es.caib.seycon.ng.model.UsuariEntity;
import es.caib.seycon.ng.servei.UsuariService;
import roles.Tothom;
import roles.federation_create_token;
import roles.selfcertificate_user;
import roles.user_query;

import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.springframework.transaction.annotation.Transactional;

@Service(serverPath = "/seycon/PushAuthenticationService", serverRole="agent")
@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	UserCredentialEntity.class,
	UserCredentialRequestEntity.class,
	ConfiguracioEntity.class,
	UsuariService.class,
	FederationMemberEntity.class,
	UsuariEntity.class,
	UserCredentialChallengeEntity.class})
public class PushAuthenticationService 
{
	public Collection<UserCredentialChallenge> sendPushAuthentication( String user ) { return null; }

	public boolean isPushAuthenticationAccepted ( UserCredentialChallenge challenge ) { return false; }

	public Collection<UserCredentialChallenge> findPushAuthentications ( String credentialId ) { return null; }

	public void responsePushAuthentication ( UserCredentialChallenge challenge, @Nullable String response ) { }

	public void updatePushAuthenticationToken (String credentialId, @Nullable String pushChannelToken, @Nullable String operatingSystem,
			@Nullable String model, @Nullable String version) {}
}
