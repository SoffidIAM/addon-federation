package com.soffid.iam.addons.federation.api;

import com.soffid.mda.annotation.Enumeration;

@Enumeration
public class SseReceiverMethod {
	public String PUSH="push";
	public String POLL="poll";
}
