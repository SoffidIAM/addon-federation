//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SC_ENTGRP" )
@Depends ({com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.common.EntityGroup.class})
public abstract class EntityGroupEntity {

	@Column (name="ENG_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="ENG_NAME", length = 100)
	public java.lang.String name;

	@Column (name="ENG_METAURL", length = 100)
	@Nullable
	public java.lang.String metadataUrl;

	@Column (name="ENG_TEN_ID")
	public TenantEntity tenant;

	@ForeignKey (foreignColumn="FED_ENT_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.FederationMemberEntity> members;

	@DaoFinder("select eg "
			+ "from com.soffid.iam.addons.federation.model.EntityGroupEntity eg "
			+ "where (:name is null or eg.name like :name) "
			+ "and eg.tenant.id=:tenantId "
			+ "order by eg.name")
	public java.util.List<com.soffid.iam.addons.federation.model.EntityGroupEntity> findByName(
		java.lang.String name) {
	 return null;
	}
}
