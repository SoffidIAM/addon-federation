package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.ProgressiveProfile;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_PROPRO")
@Depends({ProgressiveProfile.class})
public class ProgressiveProfileEntity {
	@Nullable @Identifier @Column(name = "PPR_ID")
	Long id;
	
	@Column(name="PPR_ORDER")
	Long order;
	
	@Column(name = "PPR_NAME")
	String name;
	
	@Nullable
	@Column(name = "PPR_CONDIT", length = 64000)
	String condition;

	@Nullable
	@Column(name = "PPR_FORM", length = 64000)
	String form;
	
	@Nullable
	@Column(name = "PPR_PRODEF")
	String processDefinition;

	@Column(name="PPR_TEN_ID")
	TenantEntity tenant;
	
	@Column(name="PPR_FED_ID", reverseAttribute = "progressiveProfiles")
	VirtualIdentityProviderEntity identityProvider;
}
