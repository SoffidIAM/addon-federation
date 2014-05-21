//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public abstract class PolicyCondition {

	@Nullable
	public java.lang.Long id;

	public com.soffid.iam.addons.federation.common.ConditionType type;

	public java.lang.String value;

	@Nullable
	public java.lang.Boolean ignoreCase;

	@Nullable
	public java.lang.String groupId;

	@Nullable
	public java.lang.String regex;

	@Nullable
	public java.lang.String nameId;

	@Nullable
	public java.lang.String attributeNameFormat;

	@Nullable
	public java.util.Collection<com.soffid.iam.addons.federation.common.PolicyCondition> childrenCondition;

	@Nullable
	public java.lang.Boolean negativeCondition;

	@Nullable
	public com.soffid.iam.addons.federation.common.Attribute attribute;

}
