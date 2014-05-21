//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="ATTC" )
@Depends ({com.soffid.iam.addons.federation.common.AttributePolicyCondition.class,
	com.soffid.iam.addons.federation.model.AttributePolicyEntity.class})
public abstract class AttributeConditionEntity extends com.soffid.iam.addons.federation.model.PolicyConditionEntity {

	@Column (name="PCO_ALLOW")
	@Nullable
	public boolean allow;

	@Column (name="ATTRIBUTE_POLICY")
	@Nullable
	public com.soffid.iam.addons.federation.model.AttributePolicyEntity attributePolicy;

	@DaoFinder("select en \nfrom \ncom.soffid.iam.addons.federation.model.AttributeConditionEntity en\nwhere\n(:attributePolicyId is null or en.attributePolicy.id =:attributePolicyId) \n")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeConditionEntity> findAttributeConditionByAttributePolicyId(
		java.lang.Long attributePolicyId) {
	 return null;
	}
	@DaoFinder("select en \nfrom \ncom.soffid.iam.addons.federation.model.AttributeConditionEntity en\nwhere\n(:id is null or en.id =:id) \n")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeConditionEntity> findAttributeConditionById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en \nfrom \ncom.soffid.iam.addons.federation.model..AttributeConditionEntity en\nwhere\n(:policyId is null or en.policy.id =:policyId) \n")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeConditionEntity> findAttributeConditionByPolicyId(
		java.lang.Long policyId) {
	 return null;
	}
}
