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
	public java.lang.String description;

	public java.lang.String type;

	@Nullable
	public com.soffid.iam.addons.federation.common.EntityGroup entityGroup;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue="new com.soffid.iam.addons.federation.common.FederationMember()")
	public com.soffid.iam.addons.federation.common.FederationMember federationMember;

}
