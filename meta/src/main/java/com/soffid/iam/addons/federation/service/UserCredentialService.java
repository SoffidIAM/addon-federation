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
import com.soffid.iam.addons.federation.model.SseReceiverEntity;
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
import roles.federation_create_push;
import roles.federation_create_token;
import roles.selfcertificate_user;
import roles.user_query;

import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.springframework.transaction.annotation.Transactional;

@Service(serverPath = "/seycon/UserCredentialService", serverRole="agent")
@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	UserCredentialEntity.class,
	UserCredentialRequestEntity.class,
	ConfiguracioEntity.class,
	UsuariService.class,
	FederationMemberEntity.class,
	UsuariEntity.class,
	SseReceiverEntity.class,
	SharedSignalEventsService.class})
public class UserCredentialService 
{
	@Operation ( grantees={federation_credential_query.class})
	public java.util.List<UserCredential> findUserCredentials( String user ) 
		{ return null; }

	@Operation ( grantees={federation_create_token.class, selfcertificate_user.class})
	public java.util.List<UserCredential> findMyCredentials( ) 
		{ return null; }
	
	public UserCredential findBySerial(String serial) {  return null; 	}
	
	@Operation ( grantees={federation_create_token.class})
	public UserCredential create(UserCredential credential) 
		{ return null; }
	
	
	@Operation ( grantees={federation_create_token.class, selfcertificate_user.class, federation_create_push.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void remove(UserCredential credential)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	
	public String generateChallenge() {return null;}

	public String generateNextSerial() {return null;}

	public UserCredential check ( String challenge, Map<String,Object> response) {return null;}
	
	public UserCredential updateLastUse (UserCredential uc) {return null;}

	
	@Operation(grantees= {federation_create_token.class, federation_create_push.class})
	public URI generateNewCredential (UserCredentialType type) { return null;}
		
	@Operation(grantees= {federation_credential_create.class})
	public URI generateNewCredential (UserCredentialType type, String user, boolean unsecure, @Nullable Date registerBefore, @Nullable String identityProvider) { return null;}

	@Description("Method used by the identity provider to bind the token to the user. Checks fo secure hash")
	public Usuari findUserForNewCredentialURI (String uriHash) {return null;}

	@Description("Method used by the identity provider to bind the token to the user. Checks for unsecure hashes")
	public boolean checkUserForNewCredential (String user) {return false;}

	@Description("Method used by the identity provider to bind the token to the user. Cancels an unsecure hash")
	public void cancelNewCredentialURIForUser (String user) {}

	@Description("Method used by the identity provider to bind the token to the user. Cancels a secure hash")
	public void cancelNewCredentialURI (String uriHash) {}
	
}
