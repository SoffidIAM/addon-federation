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
	@Column (name="FED_PUBID")
	public java.lang.String publicId;

	@ForeignKey (foreignColumn="PRO_VIP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.SamlProfileEntity> profiles;

	@Column (name="FED_DFIP_ID")
	@Nullable
	public com.soffid.iam.addons.federation.model.IdentityProviderEntity defaultIdentityProvider;

	@ForeignKey (foreignColumn="SPI_VIP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.ServiceProviderVirtualIdentityProviderEntity> serviceProviderVirtualIdentityProvider;

	@Column (name="ALLOW_REGISTER")
	@Nullable
	public boolean allowRegister;

	@Column (name="ALLOW_RECOVER")
	@Nullable
	public boolean allowRecover;

	@Column (name="ALLOW_CERTIFICATE")
	@Nullable
	public boolean allowCertificate;

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

	@Column (name="FED_KRBDOM", length=128)
	@Nullable
	public String kerberosDomain;

	@Column (name="FED_SSCODO")
	@Nullable
	public String ssoCookieDomain;

	@Column (name="FED_SSCONA")
	@Nullable
	public String ssoCookieName;

}
