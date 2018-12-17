//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SAMLPRO" )
@Depends ({
	com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class})
public abstract class SamlProfileEntity extends ProfileEntity {
	@Column (name="PRO_SGNRESP")
	@Nullable
	public java.lang.Long signResponses;

	@Column (name="PRO_SGNASSE")
	@Nullable
	public java.lang.Long signAssertions;

	@Column (name="PRO_SGNREQ")
	@Nullable
	public java.lang.Long signRequests;

}
