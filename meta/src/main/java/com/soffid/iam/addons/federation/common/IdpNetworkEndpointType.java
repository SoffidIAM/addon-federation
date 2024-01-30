package com.soffid.iam.addons.federation.common;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class IdpNetworkEndpointType {
	public String TLSv1_3 = "TLSv1.3";
	public String TLSv1_2 = "TLSv1.2";
	public String PLAIN = "PLAIN";
}
