package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.AuthenticationMethod;

public class AuthenticationMethodEntityDaoImpl extends AuthenticationMethodEntityDaoBase {

	public AuthenticationMethodEntity authenticationMethodToEntity(AuthenticationMethod instance) {
		AuthenticationMethodEntity entity = newAuthenticationMethodEntity();
		authenticationMethodToEntity(instance, entity, true);
        return entity;
	}
}
