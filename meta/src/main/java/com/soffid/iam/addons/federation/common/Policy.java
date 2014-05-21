//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public abstract class Policy {

	@Nullable
	public java.lang.Long id;

	@Nullable
	public java.lang.String name;

	@Nullable
	public java.util.Collection<com.soffid.iam.addons.federation.common.AttributePolicy> attributePolicy;

	@Nullable
	public com.soffid.iam.addons.federation.common.PolicyCondition condition;

}
