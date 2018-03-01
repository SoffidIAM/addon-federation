package com.soffid.iam.addons.federation.common;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class IdentityProviderType {
	public static String SOFFID = "soffid";
	public static String SAML = "saml";
	public static String OPENID_CONNECT = "openid-connect";
	public static String FACEBOOK = "facebook";
	public static String GOOGLE = "google";
	public static String LINKEDIN = "linkedin";
}
