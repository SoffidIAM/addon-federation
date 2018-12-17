//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

import es.caib.seycon.ng.comu.Password;

@ValueObject 
public class FederationMember {

	@Nullable
	public java.lang.Long id;

	public String classe;

	@Nullable
	public java.lang.String name;

	@Nullable
	public java.lang.String organization;

	@Nullable
	public java.lang.String contact;

	@Nullable
	public java.lang.String metadades;

	@Nullable
	public java.lang.String publicId;

	@Nullable
	public java.lang.String publicKey;

	@Nullable
	public java.lang.String privateKey;

	@Nullable
	public java.lang.String certificateChain;

	@Nullable
	public java.lang.String nameIdFormat;

	@Nullable
	public com.soffid.iam.addons.federation.common.EntityGroup entityGroup;

	@Nullable
	public java.util.Collection<com.soffid.iam.addons.federation.common.FederationMember> serviceProvider;

	@Nullable
	public java.util.Collection<com.soffid.iam.addons.federation.common.FederationMember> virtualIdentityProvider;

	@Nullable
	public com.soffid.iam.addons.federation.common.FederationMember defaultIdentityProvider;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue="com.soffid.iam.addons.federation.common.IdentityProviderType.SAML")
	public IdentityProviderType idpType;

	@Nullable
	public String oauthKey;

	@Nullable
	public Password oauthSecret;


	@Nullable
	public java.lang.Boolean internal;

	@Nullable
	public java.lang.String hostName;

	@Nullable
	public java.lang.String standardPort;

	@Nullable
	public java.lang.String clientCertificatePort;

	@Nullable
	public java.util.Collection<java.lang.String> virtualIdentityProviderPublicId;

	@Nullable
	public java.util.Collection<java.lang.String> serviceProviderPublicId;

	public boolean allowRegister;

	public boolean allowRecover;

	@Nullable 
	String authenticationMethods;
	
	@Nullable
	public String kerberosDomain;
	
	@Nullable
	public String ssoCookieDomain;
	
	@Nullable
	public String ssoCookieName;
	
	@Nullable
	public Boolean disableSSL;

	@Nullable
	public java.lang.String userTypeToRegister;

	@Nullable
	public java.lang.String groupToRegister;

	@Nullable
	public java.lang.String mailHost;

	@Nullable
	public java.lang.String mailSenderAddress;
	
	@Description ("Identity Provider session timeout")
	@Nullable
	Long sessionTimeout;

	@Description("Bean shell expression to generate user id")
	@Nullable
	public String uidExpression;

	@Description("Assertion consumer service path")
	@Nullable
	public String assertionPath;

	@Description ("Register new identities from remote identity providers")
	@Nullable
	Boolean registerExternalIdentities;

	@Description("Domain expression (regular expression) to detect users from this domain")
	@Nullable
	public String domainExpression;

	@Description("Script to parse the user name")
	@Nullable
	public String scriptParse;

	@Description ("Service provider type")
	@Nullable
	ServiceProviderType serviceProviderType;

	@Description("Open ID Secret")
	@Nullable
	public String openidSecret;

	@Description("Open ID Client Id")
	@Nullable
	public String openidClientId;

	@Description("Open ID URL")
	@Nullable
	public String openidUrl;

	@Description("Open ID grant type")
	@Nullable
	public String openidGrantType;

	@Description("Open ID Flow. Implicet / Authorisation code")
	@Nullable
	public String openidFlow;

}
