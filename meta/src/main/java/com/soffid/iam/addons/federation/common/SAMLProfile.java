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

}
