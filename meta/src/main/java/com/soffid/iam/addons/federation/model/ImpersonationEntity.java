package com.soffid.iam.addons.federation.model;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;

@Entity (table="SC_FEDIMP"  )
public class ImpersonationEntity {
	@Column(name="FIP_ID")
	@Identifier Long id;
	
	@Column(name="FIP_FED_ID", reverseAttribute = "impersonations")
	ServiceProviderEntity serviceProvider;
	
	@Column(name="FIP_URL")
	String url;
}
