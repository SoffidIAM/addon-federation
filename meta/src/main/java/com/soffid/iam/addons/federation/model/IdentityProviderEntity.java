//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.mda.annotation.*;

import es.caib.seycon.ng.comu.Password;

@Entity (table="" ,
		discriminatorValue="I" )
@Depends ({com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity.class})
public abstract class IdentityProviderEntity extends com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity {
	@Column(name="FED_TYPE")
	@Nullable
	public IdentityProviderType idpType;

	@Column(name="FED_OAUKEY")
	@Nullable
	public String oauthKey;

	@Column(name="FED_OAUSEC")
	@Nullable
	public String oauthSecret;


	@ForeignKey (foreignColumn="FED_DFIP_ID")
	public java.util.Collection<com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity> virtualIdentityProvider;

	@Column (name="FED_CCERPORT",
		defaultValue="\"false\"")
	@Nullable
	public java.lang.String clientCertificatePort;
	
	@Column (name="FED_KTAB", length=1024)
	@Nullable
	public String ktabFile;

	@Description ("Identity Provider session timeout")
	@Nullable
	@Column (name="FED_SETIOU")
	Long sessionTimeout;

	@Description ("Identity Provider maximum session time")
	@Nullable
	@Column (name="FED_MASEDU")
	Long maxSessionDuration;

	@Description ("Act as a identity broker")
	@Nullable
	@Column (name="FED_BROKER", defaultValue="Boolean.FALSE")
	Boolean identityBroker;

	@Description ("Register new identities from remote identity providers")
	@Nullable
	@Column (name="FED_REGEXT", defaultValue="Boolean.FALSE")
	Boolean registerExternalIdentities;

	@Column (name="FED_SSLPUB", length=4000)
	@Nullable
	@Description("SSL public key in PEM format")
	public java.lang.String sslPublicKey;

	@Column (name="FED_SSLKEY", length=4000)
	@Nullable
	@Description("SSL private key in PEM format")
	public java.lang.String sslPrivateKey;

	@Column (name="FED_SSLCER", length=4000)
	@Nullable
	@Description("SSL certificates in PEM format")
	public java.lang.String sslCertificate;

	@Column (name="FED_SSCLHE", length=4000)
	@Nullable
	@Description("HTTP Header that holds the client certificate")
	public java.lang.String sslClientCertificateHeader;

	@Column (name="FED_CAPENA")
	@Nullable
	@Description("Enable reCaptcha v3")
	public java.lang.Boolean enableCaptcha;

	@Column (name="FED_CAPKEY")
	@Nullable
	@Description("Recaptcha site key")
	public java.lang.String captchaKey;

	@Column (name="FED_CAPSEC")
	@Nullable
	@Description("Recaptcha site secret")
	public String captchaSecret;

	@Column (name="FED_CAPTHR")
	@Nullable
	@Description("Recaptcha acceptance threshold")
	public java.lang.Double captchaThreshold;

	@Description("Default language for UI. Leave empty to use browser language")
	@Column(name="FED_LANG", length = 4)
	@Nullable
	String language;
}
