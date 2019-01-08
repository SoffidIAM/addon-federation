//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="OPENID" )
@Depends ({com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class})
public abstract class OpenidProfileEntity extends ProfileEntity {
	@Column (name="PRO_AUTEPO")
	@Nullable
	String authorizationEndpoint;
	
	@Column (name="PRO_TOKEPO")
	@Nullable
	String tokenEndpoint;

	@Column (name="PRO_USEEPO")
	@Nullable
	String userInfoEndpoint;

}
