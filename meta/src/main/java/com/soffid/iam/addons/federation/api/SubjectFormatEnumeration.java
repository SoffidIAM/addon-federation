package com.soffid.iam.addons.federation.api;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class SubjectFormatEnumeration {
	public static String ACCOUNT = "account";
	public static String EMAIL = "email";
	public static String ISS_SUB = "iss_sub";
	public static String OPAQUE = "opaque";
	public static String PHONE_NUMBER = "phone_number";
	public static String DID = "did";
	public static String URI = "uri";
	
}
