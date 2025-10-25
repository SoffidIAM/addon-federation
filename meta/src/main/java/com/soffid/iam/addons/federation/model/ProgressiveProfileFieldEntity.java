package com.soffid.iam.addons.federation.model;

import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table="SC_PRPRFI")
public class ProgressiveProfileFieldEntity {
	@Nullable @Identifier @Column(name="PPF_ID")
	Long id;
	
	@Column(name="PPF_TEN_ID")
	TenantEntity tenant;
	
	@Column(name="PPF_PPR_ID", reverseAttribute = "fields")
	ProgressiveProfileEntity profile;
	
	@Column(name="PPF_FIELD")
	String field;
}
