//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="S" )
@Depends ({com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class})
public abstract class ServiceProviderEntity extends com.soffid.iam.addons.federation.model.FederationMemberEntity {
	@Column(name="FED_SPTYP")
	@Nullable
	ServiceProviderType serviceProviderType;
	
	@Column (name="FED_PUBID")
	@Nullable
	public java.lang.String publicId;

	@Column (name="FED_NIDFOR")
	@Nullable
	public java.lang.String nameIdFormat;

	@ForeignKey (foreignColumn="SPI_SP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity> serviceProviderVirtualIdentityProvider;

	@Column(name="FED_UID", length=2000)
	@Nullable
	public String uidExpression;

	@Column(name="FED_OIDSEC", length=150)
	@Nullable
	public String openidSecret;

	@Column(name="FED_OIDKEY", length=150)
	@Nullable
	public String openidClientId;

	@Column(name="FED_OIDURL", length=150)
	@Nullable
	public String openidUrl;

	@Column(name="FED_OIDGRA", length=50)
	@Nullable
	public String openidGrantType;

	@Column(name="FED_OIDFLO", length=50)
	@Nullable
	public String openidFlow;
	
	@DaoFinder("select sp "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderEntity sp "
			+ "where (sp.openidClientId = :openidClientId) and sp.tenant.id=:tenantId")
	public ServiceProviderEntity findByClientId(
			java.lang.String openidClientId) {
		 return null;
		}

}
