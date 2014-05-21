//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="SC_ENTGRP" )
@Depends ({com.soffid.iam.addons.federation.model.FederationMemberEntity.class,
	com.soffid.iam.addons.federation.common.EntityGroup.class})
public abstract class EntityGroupEntity {

	@Column (name="ENG_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="ENG_NAME")
	public java.lang.String name;

	@Column (name="ENG_METAURL")
	@Nullable
	public java.lang.String metadataUrl;

	@ForeignKey (foreignColumn="FED_ENT_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.FederationMemberEntity> members;

	@DaoFinder("select eg\nfrom\ncom.soffid.iam.addons.federation.model.EntityGroupEntity eg\nwhere\n(:name is null or eg.name like :name)\norder by eg.name")
	public java.util.List<com.soffid.iam.addons.federation.model.EntityGroupEntity> findByName(
		java.lang.String name) {
	 return null;
	}
}
