package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_ADAAUT")
@Depends({
	AuthenticationMethod.class
})
public class AuthenticationMethodEntity {
	@Identifier
	@Column(name = "AAU_ID")
	Long id;
	
	@Column(name = "AAU_FED_ID", reverseAttribute = "extendedAuthenticationMethods")
	VirtualIdentityProviderEntity identityProvider;
	
	@Column(name = "AAU_ORDER")
	@Nullable
	Long order;

	@Column(name = "AAU_DESCRI")
	@Nullable
	String description;

	@Column(name = "AAU_EXPR")
	String expression;
	
	@Column(name = "AAU_AUTHE")
	String authenticationMethods;
}
