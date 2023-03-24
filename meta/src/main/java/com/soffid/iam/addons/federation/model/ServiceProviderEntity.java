//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import java.util.Collection;
import java.util.Date;

import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.model.DispatcherEntity;

@Entity (table="" ,
		discriminatorValue="S" )
@Depends ({com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class})
public abstract class ServiceProviderEntity extends com.soffid.iam.addons.federation.model.FederationMemberEntity {
	@Column(name="FED_SPTYP")
	@Nullable
	ServiceProviderType serviceProviderType;
	
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

	// Legacy column
	@Column(name="FED_OIDURL", length=150)
	@Nullable
	public String openidUrl;

	@Description("Open ID FrontChannel Logout URL")
	@Nullable
	@Column(name="FED_OIFRLOL", length=250)
	public String openidLogoutUrlFront;

	@Description("Open ID Backchannel Logout URL")
	@Nullable
	@Column(name="FED_OIBALOL", length=250)
	public String openidLogoutUrlBack;

	@Description("Open ID Sector Identifier URL")
	@Nullable
	@Column(name="FED_OISEIDL", length=250)
	public String openidSectorIdentifierUrl;

	@Column(name="FED_OIDMEC", length=50)
	@Description("Open ID mechanisms (comma separated list of values): Implicit, AuthorizationCode, Password, PasswordClientCredentals")
	@Nullable
	public String openidMechanism;

	@Description("Allow users with accounts on the system")
	@Nullable
	@Column (name="FED_DIS_ID")
	DispatcherEntity system;

	// Radius attributes
	@Column(name="FED_SRCIP", length=150)
	@Description("Source IPs or IP ranges, for Radius clients")
	@Nullable
	public String sourceIps;

	@Column(name="FED_RADSEC", length=50)
	@Description("Radius secret")
	@Nullable
	public String radiusSecret;
	
	@Description("Ask consent to share information with this service provider")
	@Column (name="FED_CONSEN")
	@Nullable
	public Boolean consent;

	@Description("Dynamic registration token")
	@Column(name="FED_REGTOK", length = 128)
	@Nullable
	String registrationToken;

	@Description("Dynamic registration token expiration")
	@Column(name="FED_RETOEX")
	@Nullable
	Date registrationTokenExpiration;
	
	@Description("Dynamic registration servers allowed")
	@Column(name="FED_RETONU")
	@Nullable
	Integer maxRegistrations;
	

	@Description("Dynamic registration server")
	@Column(name="FED_REG_ID", reverseAttribute = "registered")
	@Nullable
	ServiceProviderEntity dynamicRegistrationServer;
	
	@DaoFinder("select sp "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderEntity sp "
			+ "where (sp.openidClientId = :openidClientId) and sp.tenant.id=:tenantId")
	public ServiceProviderEntity findByClientId(
			java.lang.String openidClientId) {
		 return null;
		}

	@DaoFinder("select sp "
			+ "from com.soffid.iam.addons.federation.model.ServiceProviderEntity sp "
			+ "where sp.dynamicRegistrationServer.publicId = :registrationServer and sp.tenant.id=:tenantId")
	public Collection<ServiceProviderEntity> findByDynamicRegistrationServer(
			java.lang.String registrationServer) {
		 return null;
	}

}
