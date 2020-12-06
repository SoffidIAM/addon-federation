package com.soffid.iam.addons.federation.common;

import java.util.Date;

import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class OauthToken {
	@Nullable
	@Identifier
	public java.lang.Long id;

	String identityProvider;
	
	String serviceProvider;
	
	@Nullable
	String authenticationMethod;
	
	@Nullable
	String user;
	
	@Nullable
	String authorizationCode;
	
	@Nullable
	String token;
	
	@Nullable
	String refreshToken;
	
	@Nullable
	Date expires;
	
	Date created;
	
	Date authenticated;
	
	@Nullable
	Long sessionId;

	@Nullable
	String sessionKey;
}
