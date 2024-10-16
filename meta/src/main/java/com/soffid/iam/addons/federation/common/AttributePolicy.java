//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class AttributePolicy {

	@Nullable
	public java.lang.Long id;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "new com.soffid.iam.addons.federation.common.Attribute()")
	public com.soffid.iam.addons.federation.common.Attribute attribute;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "new com.soffid.iam.addons.federation.common.AttributePolicyCondition()")
	public com.soffid.iam.addons.federation.common.AttributePolicyCondition attributePolicyCondition;

	@Nullable
	public java.lang.Long policyId;

}
