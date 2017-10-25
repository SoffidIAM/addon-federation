//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class EntityGroupMember {

	@Nullable
	public java.lang.String descripcio;

	public java.lang.String tipus;

	@Nullable
	public com.soffid.iam.addons.federation.common.EntityGroup entityGrupPare;

	@Nullable
	public com.soffid.iam.addons.federation.common.FederationMember federationMember;

}
