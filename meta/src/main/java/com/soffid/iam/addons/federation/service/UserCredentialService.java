//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.service;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.model.ConfiguracioEntity;
import es.caib.seycon.ng.model.UsuariEntity;
import roles.Tothom;
import roles.user_query;

import java.util.Map;

import org.springframework.transaction.annotation.Transactional;

@Service(serverPath = "/seycon/UserCredentialService", serverRole="agent")
@Depends ({es.caib.seycon.ng.servei.ConfiguracioService.class,
	UserCredentialEntity.class,
	ConfiguracioEntity.class,
	UsuariEntity.class})
public class UserCredentialService 
{
	@Operation ( grantees={user_query.class})
	public java.util.List<UserCredential> findUserCredentials( String user ) 
		{ return null; }

	@Operation ( grantees={Tothom.class})
	public java.util.List<UserCredential> findMyCredentials( ) 
		{ return null; }
	
	public UserCredential findBySerial(String serial) {  return null; 	}
	
	@Operation ( grantees={Tothom.class})
	public UserCredential create(UserCredential credential) 
		{ return null; }
	
	
	@Operation ( grantees={Tothom.class})
	@Transactional(rollbackFor={java.lang.Exception.class})
	public void remove(UserCredential credential)
		throws es.caib.seycon.ng.exception.InternalErrorException {
	}
	
	public String generateChallenge() {return null;}

	
	public String generateNextSerial() {return null;}

	public UserCredential check ( String challenge, Map<String,Object> response) {return null;}
}
