package com.soffid.iam.addons.federation.api;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class TokenType {
	public static String TOKEN_OAUTH = "OPENID";
	public static String TOKEN_CAS = "CAS";
}
