//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="S" )
@Depends ({com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class})
public abstract class ServiceProviderEntity extends com.soffid.iam.addons.federation.model.FederationMemberEntity {

	@Column (name="FED_PUBID")
	@Nullable
	public java.lang.String publicId;

	@Column (name="FED_NIDFOR")
	@Nullable
	public java.lang.String nameIdFormat;

	@Column (name="FED_CERCHA")
	@Nullable
	public java.lang.String certificateChain;

	@ForeignKey (foreignColumn="SPI_SP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity> serviceProviderVirtualIdentityProvider;

}
