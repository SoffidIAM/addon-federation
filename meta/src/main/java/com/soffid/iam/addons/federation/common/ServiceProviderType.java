package com.soffid.iam.addons.federation.common;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class ServiceProviderType {
//	public static String SOFFID = "soffid";
	public static String SAML = "saml";
	public static String SOFFID_SAML = "soffid-saml";
	public static String OPENID_CONNECT = "openid-connect";
	public static String OPENID_REGISTER = "openid-dynamic-register";
	public static String RADIUS = "radius";
	public static String CAS = "cas";
	public static String TACACSP = "tacacs+";
	public static String WS_FEDERATION = "ws-fed";
}
