package com.soffid.iam.addons.federation.model;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;

import es.caib.seycon.ng.model.RolEntity;

@Entity(table = "SC_ALSCRO")
@Depends({RolEntity.class})
public class AllowedScopeRoleEntity {
	@Column(name = "ASR_ID")
	@Identifier Long id;
	
	@Column(name="ASR_SAS_ID", reverseAttribute = "roles")
	AllowedScopeEntity scope;
	
	@Column(name="ASR_ROL_ID")
	Long roleId;
}
