package com.soffid.iam.addons.federation.rest.json;

public class ValidateDomainJSONResponse {

	String exists = null;
	String identityProvider = null;

	public String getExists() {
		return exists;
	}

	public void setExists(String exists) {
		this.exists = exists;
	}

	public String getIdentityProvider() {
		return identityProvider;
	}

	public void setIdentityProvider(String identityProvider) {
		this.identityProvider = identityProvider;
	}
}
