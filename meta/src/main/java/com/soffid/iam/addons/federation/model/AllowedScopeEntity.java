package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;

import es.caib.seycon.ng.model.RolEntity;

@Entity(table = "SC_SPALSC")
@Depends({AllowedScope.class, RolEntity.class})
public class AllowedScopeEntity {
	@Column(name = "SAS_ID")
	@Identifier Long id;
	
	@Column(name="SAS_FED_ID", reverseAttribute = "allowedScopes")
	ServiceProviderEntity serviceProvider;
	
	@Column(name="SAS_SCOPE", length = 256)
	String scope;
}
