//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="SC_SPVIPR" )
@Depends ({com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class,
	com.soffid.iam.addons.federation.model.ServiceProviderEntity.class})
public abstract class ServiceProviderVirtualIdentityProviderEntity {

	@Column (name="SPI_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="SPI_VIP_ID")
	public com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity virtualIdentityProvider;

	@Column (name="SPI_SP_ID")
	public com.soffid.iam.addons.federation.model.ServiceProviderEntity serviceProvider;

	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity fm "
			+ "where (fm.virtualIdentityProvider.id=:vipId) and "
			+ "fm.virtualIdentityProvider.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity> findByVIP(
		java.lang.Long vipId) {
	 return null;
	}
	@DaoFinder("select fm "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity fm "
			+ "where (fm.serviceProvider.id=:spId) and "
			+ "fm.serviceProvider.tenant.id=:tenantId")
	public java.util.List<com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity> findBySP(
		java.lang.Long spId) {
	 return null;
	}
}
