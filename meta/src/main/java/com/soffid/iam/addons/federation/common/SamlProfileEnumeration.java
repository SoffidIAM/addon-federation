//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@Enumeration 
public class SamlProfileEnumeration {

	public java.lang.String SAML2_ECP="SAML2ECPProfile";

	public java.lang.String SAML1_AR="SAML1ArtifactResolutionProfile";

	public java.lang.String SAML1_AQ="SAML1AttributeQueryProfile";

	public java.lang.String SAML2_SSO="SAML2SSOProfile";

	public java.lang.String SAML2_AR="SAML2ArtifactResolutionProfile";

	public java.lang.String SAML2_AQ="SAML2AttributeQueryProfile";

	public java.lang.String SAML_PRO="SAMLProfile";

	public java.lang.String OPENID="OpenidProfile";

	public java.lang.String RADIUS="RadiusProfile";

	public java.lang.String CAS="CasProfile";

	public java.lang.String TACACS_PLUS="Tacacs+Profile";
}
