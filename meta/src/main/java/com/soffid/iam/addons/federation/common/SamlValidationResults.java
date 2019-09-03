package com.soffid.iam.addons.federation.common;

import java.util.Map;

import com.soffid.mda.annotation.Attribute;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

import es.caib.seycon.ng.comu.Usuari;

@ValueObject
public class SamlValidationResults {
	boolean valid;

	boolean expired;

	String identityProvider;
	
	String principalName;
	
	String sessionCookie;
	
	@Nullable
	@Attribute(defaultValue="new java.util.HashMap<String,Object>()")
	Map<String,Object> attributes;
	
	@Nullable
	Usuari user;
	
	String failureReason;
}
