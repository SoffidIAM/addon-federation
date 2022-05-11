package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;

@Entity(table = "SC_OATOSC")
public class OauthTokenScopeEntity {
	@Column (name="TSC_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="TSC_TOK_ID", reverseAttribute = "scopes")
	public OauthTokenEntity token;
	
	@Column (name="TSC_SCOPE", length=200)
	public String scope;
	
}
