//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SC_ATTRIB" )
@Depends ({com.soffid.iam.addons.federation.common.Attribute.class,
	com.soffid.iam.addons.federation.model.AttributePolicyEntity.class,
	com.soffid.iam.addons.federation.model.PolicyConditionEntity.class})
public abstract class AttributeEntity {

	@Column (name="ATT_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="ATT_SHNAME")
	@Nullable
	public java.lang.String shortName;

	@Column (name="ATT_OID")
	@Nullable
	public java.lang.String oid;

	@ForeignKey (foreignColumn="ATP_ATT_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.AttributePolicyEntity> attributePolicy;

	@Column (name="ATT_OPIDNA")
	@Nullable
	public java.lang.String openidName;
	
	@Column (name="ATT_NAME")
	@Nullable
	public java.lang.String name;
	

	@Column (name="ATT_EXPR", length=2000)
	@Nullable
	public java.lang.String value;
	
	@Column(name="ATT_TEN_ID")
	@Nullable
	public TenantEntity tenant;

	@ForeignKey (foreignColumn="PCO_ATT_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.PolicyConditionEntity> condicions;

	@DaoFinder
	public com.soffid.iam.addons.federation.model.AttributeEntity findById(
		java.lang.Long id) {
	 return null;
	}
	@DaoFinder
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeEntity> findByOid(
		java.lang.String oid) {
	 return null;
	}
	@DaoFinder
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeEntity> findByShortName(
		java.lang.String shortName) {
	 return null;
	}
	@DaoFinder
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeEntity> findByName(
		java.lang.String name) {
	 return null;
	}
	@DaoFinder("from com.soffid.iam.addons.federation.model.AttributeEntity as attributeEntity "
			+ "where (:name is null or attributeEntity.name like :name) and "
			+ "(:shortName is null or attributeEntity.shortName like :shortName) and "
			+ "(:oid is null or attributeEntity.oid like :oid) and "
			+ "tenant.id = :tenantId "
			+ "order by attributeEntity.name")
	public java.util.List<com.soffid.iam.addons.federation.model.AttributeEntity> findByNameShortNameOid(
		java.lang.String name, 
		java.lang.String shortName, 
		java.lang.String oid) {
	 return null;
	}
}
