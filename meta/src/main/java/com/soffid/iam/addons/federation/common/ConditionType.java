//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@Enumeration 
public class ConditionType {

	public java.lang.String ANY="basic:ANY";

	public java.lang.String AND="basic:AND";

	public java.lang.String OR="basic:OR";

	public java.lang.String AttributeRequesterString="basic:AttributeRequesterString";

	public java.lang.String AttributeIssuerString="basic:AttributeIssuerString";

	public java.lang.String PrincipalNameString="basic:PrincipalNameString";

	public java.lang.String AuthenticationMethodString="basic:AuthenticationMethodString";

	public java.lang.String AttributeValueString="basic:AttributeValueString";

//	public java.lang.String AttributeScopeString="basic:AttributeScopeString";

	public java.lang.String AttributeRequesterRegex="basic:AttributeRequesterRegex";

	public java.lang.String AttributeIssuerRegex="basic:AttributeIssuerRegex";

	public java.lang.String PrincipalNameRegex="basic:PrincipalNameRegex";

	public java.lang.String AuthenticationMethodRegex="basic:AuthenticationMethodRegex";

	public java.lang.String AttributeValueRegex="basic:AttributeValueRegex";

//	public java.lang.String AttributeScopeRegex="basic:AttributeScopeRegex";

//	public java.lang.String Script="basic:Script";

	public java.lang.String AttributeRequesterInEntityGroup="saml:AttributeRequesterInEntityGroup";

	public java.lang.String AttributeIssuerInEntityGroup="saml:AttributeIssuerInEntityGroup";

	public java.lang.String AttributeIssuerNameIDFormatExactMatch="saml:AttributeIssuerNameIDFormatExactMatch";

	public java.lang.String AttributeIssuerEntityAttributeExactMatch="saml:AttributeIssuerEntityAttributeExactMatch";

	public java.lang.String AttributeIssuerEntityAttributeRegexMatch="saml:AttributeIssuerEntityAttributeRegexMatch";

	public java.lang.String AttributeRequesterEntityAttributeRegexMatch="saml:AttributeRequesterEntityAttributeRegexMatch";

	public java.lang.String AttributeRequesterEntityAttributeExactMatch="saml:AttributeRequesterEntityAttributeExactMatch";

	public java.lang.String AttributeRequesterNameIDFormatExactMatch="saml:AttributeRequesterNameIDFormatExactMatch";

}
