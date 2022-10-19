//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;

import java.util.List;
import java.util.Set;

import com.soffid.mda.annotation.Attribute;
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
	@Description("SSL private key in PEM format")
	public java.lang.String sslPrivateKey;

	@Nullable
	@Description("SSL public key in PEM format")
	public java.lang.String sslPublicKey;

	@Nullable
	@Description("SSL certificates in PEM format")
	public java.lang.String sslCertificate;

	@Nullable
	@Description("HTTP Header that holds the client certificate")
	public java.lang.String sslClientCertificateHeader;

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

	@Description ("Workflow for new user aproval")
	@Nullable
	String registerWorkflow;

	public boolean allowRecover;

	@Nullable 
	String authenticationMethods;
	
	@Nullable 
	Boolean alwaysAskForCredentials;

	@Nullable
	public String kerberosDomain;
	
	@Nullable
	public String ssoCookieDomain;
	
	@Nullable
	public String ssoCookieName;
	
	@Nullable
	public Boolean consent;

	@Nullable
	@Attribute(defaultValue = "Boolean.FALSE")
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

	@Description ("Identity Provider session timeout for oAuth sessions (in seconds)")
	@Nullable
	Long oauthSessionTimeout;

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
	@Attribute(defaultValue = "new java.util.LinkedList()")
	public List<String> openidUrl;

	@Description("Open ID RP-initiatedLogout URL")
	@Nullable
	@Attribute(defaultValue = "new java.util.LinkedList()")
	public List<String> openidLogoutUrl;

	@Description("Open ID FrontChannel Logout URL")
	@Nullable
	public String openidLogoutUrlFront;

	@Description("Open ID Backchannel Logout URL")
	@Nullable
	public String openidLogoutUrlBack;

	@Description("Login hint script")
	@Attribute(defaultValue = "\"loginHint\"")
	@Nullable
	public String loginHintScript;

	@Description("Open ID mechanisms: Implicit, AuthorizationCode, Password, PasswordClientCredentals")
	@Attribute(defaultValue="new java.util.HashSet()")
	@Nullable
	public Set<String> openidMechanism;

	// Radius attributes
	@Description("Source IPs or IP ranges, for Radius clients")
	@Nullable
	public String sourceIps;

	@Description("Radius secret")
	@Nullable
	public Password radiusSecret;

	@Description("Kerberos keytabs")
	@Attribute(defaultValue="new java.util.LinkedList()")
	@Nullable
	public List<KerberosKeytab> keytabs;

	@Nullable
	@Attribute(defaultValue="new java.util.LinkedList()")
	public List<AuthenticationMethod> extendedAuthenticationMethods;

	@Nullable
	@Attribute(defaultValue="new java.util.LinkedList()")
	public List<String> impersonations;

	@Nullable
	@Description("List of roles to get access to this service provider")
	@Attribute(defaultValue="new java.util.LinkedList()")
	public List<String> roles;

	@Nullable
	@Description("The service provider requires account in the system")
	public String system;

	@Nullable
	@Description("List of oauth scopes for this service provider")
	@Attribute(defaultValue="new java.util.LinkedList()")
	public List<AllowedScope> allowedScopes;
}
