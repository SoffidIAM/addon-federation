package com.soffid.iam.addons.federation.api;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class SubjectSourceEnumeration {
	public static String SYSTEM = "S";
	public static String OAUTH_ATTRIBUTE = "A";
	public static String EXPRESSION = "E";
}
