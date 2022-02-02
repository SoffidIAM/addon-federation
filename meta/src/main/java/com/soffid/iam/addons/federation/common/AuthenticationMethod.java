package com.soffid.iam.addons.federation.common;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class AuthenticationMethod {
	String expression;
	
	String description;

	String authenticationMethods;

	@Nullable 
	Boolean alwaysAskForCredentials;
}
