//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SC_POLICY" )
@Depends ({com.soffid.iam.addons.federation.common.Policy.class,
	com.soffid.iam.addons.federation.model.AttributePolicyEntity.class,
	com.soffid.iam.addons.federation.model.PolicyConditionEntity.class,
	com.soffid.iam.addons.federation.model.FederationMemberEntity.class})
public abstract class PolicyEntity {

	@ForeignKey (foreignColumn="ATP_POL_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.AttributePolicyEntity> attributePolicy;

	@Column (name="POL_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="POL_NAME")
	public java.lang.String name;

	@Column (name="POL_CON_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.PolicyConditionEntity condition;

	@Column (name="POL_TEN_ID")
	public TenantEntity tenant;
	
	@DaoFinder
	public com.soffid.iam.addons.federation.model.PolicyEntity findById(
		java.lang.Long id) {
	 return null;
	}

	@DaoFinder
	public com.soffid.iam.addons.federation.model.PolicyEntity findByName(
		java.lang.String name) {
	 return null;
	}

	@DaoFinder("from com.soffid.iam.addons.federation.model.PolicyEntity as policyEntity "
			+ "where policyEntity.identiyProvider.id = :id and policyEntity.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.PolicyEntity> findByidentiyProviderId(
		java.lang.Long id) {
	 return null;
	}
}
