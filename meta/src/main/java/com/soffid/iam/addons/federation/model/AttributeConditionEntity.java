//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
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

	@DaoFinder("select en \n"
			+ "from com.soffid.iam.addons.federation.model.AttributeConditionEntity en "
			+ "where (:attributePolicyId is null or en.attributePolicy.id =:attributePolicyId) and "
			+ " en.tenant.id=:tenantId\n")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeConditionEntity> findAttributeConditionByAttributePolicyId(
		java.lang.Long attributePolicyId) {
	 return null;
	}
	@DaoFinder("select en \n"
			+ "from com.soffid.iam.addons.federation.model.AttributeConditionEntity en "
			+ "where (:id is null or en.id =:id) and en.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeConditionEntity> findAttributeConditionById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder("select en "
			+ "from com.soffid.iam.addons.federation.model..AttributeConditionEntity en"
			+ "where (:policyId is null or en.policy.id =:policyId)  and en.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeConditionEntity> findAttributeConditionByPolicyId(
		java.lang.Long policyId) {
	 return null;
	}
}
