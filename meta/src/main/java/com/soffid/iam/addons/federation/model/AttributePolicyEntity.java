//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="SC_ATTPOL" )
@Depends ({com.soffid.iam.addons.federation.common.AttributePolicy.class,
	com.soffid.iam.addons.federation.model.AttributeEntity.class,
	com.soffid.iam.addons.federation.model.AttributeConditionEntity.class,
	com.soffid.iam.addons.federation.model.PolicyEntity.class})
public abstract class AttributePolicyEntity {

	@Column (name="ATP_POL_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.PolicyEntity policy;

	@Column (name="ATP_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="ATP_ATT_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.AttributeEntity attribute;

	@Column (name="ATP_CON_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.AttributeConditionEntity attributeCondition;

}
