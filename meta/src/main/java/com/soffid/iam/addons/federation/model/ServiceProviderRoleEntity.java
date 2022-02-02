//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.model.DispatcherEntity;
import es.caib.seycon.ng.model.RolEntity;

@Entity (table="SC_FEDROL" ,
		discriminatorValue="S" )
@Depends ({com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class})
public abstract class ServiceProviderRoleEntity {
	@Column(name="FRO_ID")
	@Nullable @Identifier Long id; 

	@Column(name="FRO_FED_ID", reverseAttribute = "roles")
	ServiceProviderEntity serviceProvider;
	
	@Column (name="FRO_ROL_ID")
	RolEntity role;
}
