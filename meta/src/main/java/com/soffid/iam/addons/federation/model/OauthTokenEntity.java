package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_OAUTOK")
@Depends({OauthToken.class})
public class OauthTokenEntity {
	@Column (name="TOK_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="TOK_IDP")
	String identityProvider;
	
	@Column (name="TOK_SP")
	String serviceProvider;
	
	@Nullable
	@Column (name="TOK_AUTMET")
	String authenticationMethod;

	@Nullable
	@Column (name="TOK_USER")
	String user;
	
	@Nullable
	@Column (name="TOK_AUTCOD")
	String authorizationCode;
	
	@Nullable
	@Column (name="TOK_TOKEN")
	String token;
	
	@Column (name="TOK_REFTOK")
	@Nullable
	String refreshToken;
	
	@Column (name="TOK_EXPIRES")
	@Nullable
	Date expires;
	
	@Column (name="TOK_AUTHEN")
	Date authenticated;
	
	@Column (name="TOK_CREATED")
	Date created;
	
	@Column (name="TOK_SESSIO")
	@Nullable
	Long sessionId;
	
	@Column (name="TOK_SESKEY")
	@Nullable
	String sessionKey;
	
	@Column (name="TOK_TEN_ID")
	TenantEntity tenant;
	
	OauthTokenEntity findByAuthorizationCode(String authorizationCode) { return null;}

	OauthTokenEntity findByToken(String token) { return null;}

	OauthTokenEntity findByRefreshToken(String refreshToken) { return null;}
}

@Index(entity = OauthTokenEntity.class, name = "SC_OAUTOK_TOK_UK", columns = {"TOK_TEN_ID", "TOK_TOKEN"})
class UniqueTokenIndex {}

@Index(entity = OauthTokenEntity.class, name = "SC_OAUTOK_REF_UK", columns = {"TOK_TEN_ID", "TOK_REFTOK"})
class UniqueRefreshTokenIndex {}

@Index(entity = OauthTokenEntity.class, name = "SC_OAUTOK_AUT_UK", columns = {"TOK_TEN_ID", "TOK_AUTCOD"})
class UniqueAuthorizationCodeIndex {}
