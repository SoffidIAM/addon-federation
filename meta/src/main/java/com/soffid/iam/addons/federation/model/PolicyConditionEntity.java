//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="SC_POLCON" ,
		discriminatorValue="POLC" ,
		discriminatorColumn="PCO_CLASSE" )
@Depends ({com.soffid.iam.addons.federation.common.PolicyCondition.class,
	com.soffid.iam.addons.federation.model.AttributeEntity.class,
	com.soffid.iam.addons.federation.model.PolicyConditionEntity.class,
	com.soffid.iam.addons.federation.model.PolicyEntity.class})
public abstract class PolicyConditionEntity {

	@Column (name="PCO_TYPE")
	public com.soffid.iam.addons.federation.common.ConditionType type;

	@Column (name="PCO_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="PCO_VALUE")
	@Nullable
	public java.lang.String value;

	@Column (name="PCO_IGNCAS")
	@Nullable
	public boolean ignoreCase;

	@Column (name="PCO_GRPID")
	@Nullable
	public java.lang.String groupId;

	@Column (name="PCO_REGEX")
	@Nullable
	public java.lang.String regex;

	@Column (name="PCO_NAMEID")
	@Nullable
	public java.lang.String nameId;

	@Column (name="PCO_ATTNAF")
	@Nullable
	public java.lang.String attributeNameFormat;

	@Column (name="PCO_ACD_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.PolicyConditionEntity attributeCondition;

	@ForeignKey (foreignColumn="PCO_ACD_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.PolicyConditionEntity> condition;

	@Column (name="POLICY")
	@Nullable
	public com.soffid.iam.addons.federation.model.PolicyEntity policy;

	@Column (name="PCO_NEGAT")
	@Nullable
	public boolean negativeCondition;

	@Column (name="PCO_ATT_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.AttributeEntity attribute;

	@DaoFinder("select en \nfrom \ncom.soffid.iam.addons.federation.model.PolicyConditionEntity en\nwhere\n(:policyId is null or en.policy.id =:policyId) \n")
	public java.util.List<com.soffid.iam.addons.federation.model.PolicyConditionEntity> findByPolicyId(
		java.lang.Long policyId) {
	 return null;
	}
	@DaoFinder("select en \nfrom \ncom.soffid.iam.addons.federation.model.PolicyConditionEntity en\nwhere\n(:id is null or en.id =:id) \n")
	public java.util.List<com.soffid.iam.addons.federation.model.PolicyConditionEntity> findPolicyConditionById(
		java.lang.Long id) {
	 return null;
	}
}
