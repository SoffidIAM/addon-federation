//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class SAMLProfile {

	@Nullable
	public java.lang.Long id;

	public com.soffid.iam.addons.federation.common.SamlProfileEnumeration classe;

	@Nullable
	public com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration signResponses;

	@Nullable
	public com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration signAssertions;

	@Nullable
	public com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration signRequests;

	@Nullable
	public java.lang.Boolean enabled;

	@Nullable
	public java.lang.String outboundArtifactType;

	@Nullable
	public java.lang.String assertionLifetime;

	@Nullable
	public com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration encryptAssertions;

	@Nullable
	public com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration encryptNameIds;

	@Nullable
	public java.lang.Long assertionProxyCount;

	@Nullable
	public java.lang.Boolean includeAttributeStatement;

	@Nullable
	public java.lang.String localityAddress;

	@Nullable
	public java.lang.String localityDNSName;

	@Nullable
	public java.lang.String maximumSPSessionLifetime;

	@Nullable
	public com.soffid.iam.addons.federation.common.FederationMember identityProvider;

	@Nullable
	String authorizationEndpoint;
	
	@Nullable
	String tokenEndpoint;

	@Nullable
	String userInfoEndpoint;

	@Nullable
	String revokeEndpoint;
	
	@Nullable
	String logoutEndpoint;
	
	// Radius servicos
	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "1812")
	Integer authPort;
	
	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "1813")
	Integer acctPort;
	
	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "false")
	Boolean pap;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "true")
	Boolean chap;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "true")
	Boolean msChap;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "true")
	Boolean ascii;

	@Column (name="PRO_SECPOR")
	@Nullable
	Integer securePort;

	@Column (name="PRO_FRRAPO")
	@Nullable
	Integer freeRadiusPort;

	@Nullable
	@com.soffid.mda.annotation.Attribute(defaultValue = "true")
	Boolean ssl;
}
