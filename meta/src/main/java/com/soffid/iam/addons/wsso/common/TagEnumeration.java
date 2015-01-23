package com.soffid.iam.addons.wsso.common;

import com.soffid.mda.annotation.Enumeration;
import com.soffid.mda.annotation.ValueObject;

@Enumeration
public class TagEnumeration {
	public final String PROXY_PASS="ProxyPass";
	public final String PROXY_PASS_REVERSE="ProxyPassReverse";
	public final String WSSO_POST="SoffidPostData";
	public final String WSSO_SCRIPT="SoffidOnLoadScript";
	public final String WSSO_BASIC_AUTH="SoffidBasicAuthentication";
	public final String SAML_AUTHENTICATION_TYPE="SamlAuthenticationType";
	public final String SAML_SERVICE_PROVIDER="SamlServiceProvider";
	public final String AUTHORITZATION="Requires";
	public final String CONDITION="If";
	public final String REWRITE_SET="RewriteSet";
	public final String REWRITE_COND="RewriteCondition";
	public final String REWRITE_RULE="RewriteRule";
}
