//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="V" )
@Depends ({com.soffid.iam.addons.federation.model.SamlProfileEntity.class,
	com.soffid.iam.addons.federation.model.IdentityProviderEntity.class,
	com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity.class,
	es.caib.seycon.ng.model.TipusUsuariEntity.class,
	es.caib.seycon.ng.model.GrupEntity.class})
public abstract class VirtualIdentityProviderEntity extends com.soffid.iam.addons.federation.model.FederationMemberEntity {
	@ForeignKey (foreignColumn="PRO_VIP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.ProfileEntity> profiles;

	@Column (name="FED_DFIP_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.IdentityProviderEntity defaultIdentityProvider;

	@ForeignKey (foreignColumn="SPI_VIP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity> serviceProviderVirtualIdentityProvider;

	@Column (name="ALLOW_REGISTER")
	@Nullable
	public boolean allowRegister;

	@Description ("Workflow for new user aproval")
	@Nullable
	@Column (name="FED_REGBPM")
	String registerWorkflow;

	@Column (name="ALLOW_RECOVER")
	@Nullable
	public boolean allowRecover;

	@Column (name="USER_TYPE_TO_REGISTER")
	@Nullable
	public es.caib.seycon.ng.model.TipusUsuariEntity userTypeToRegister;

	@Column (name="GROUP_TO_REGISTER")
	@Nullable
	public es.caib.seycon.ng.model.GrupEntity groupToRegister;

	@Column (name="MAIL_HOST")
	@Nullable
	public java.lang.String mailHost;

	@Column (name="MAIL_SENDER_ADDRESS")
	@Nullable
	public java.lang.String mailSenderAddress;

	@Column (name="FED_KERBEROS")
	@Nullable
	public Boolean enableKerberos;

	@Column (name="FED_AUTMET")
	@Nullable
	public String authenticationMethods;

	@Column(name="FED_ASKCRE")
	@Nullable 
	Boolean alwaysAskForCredentials;

	@Column (name="ALLOW_CERTIFICATE")
	@Nullable
	public boolean allowCertificate;

	@Column (name="FED_KRBDOM", length=128)
	@Nullable
	public String kerberosDomain;

	@Column (name="FED_SSCODO")
	@Nullable
	public String ssoCookieDomain;

	@Column (name="FED_SSCONA")
	@Nullable
	public String ssoCookieName;

	@Column (name="FED_LOGHIN", length = 4096)
	@Nullable
	public String loginHintScript;

	@Column (name="FED_STOUSE")
	@Nullable
	@Description("Store user name in browser cookie")
	public java.lang.Boolean storeUser;
}

