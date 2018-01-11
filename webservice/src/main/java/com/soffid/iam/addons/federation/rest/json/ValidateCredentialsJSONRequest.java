package com.soffid.iam.addons.federation.rest.json;

public class ValidateCredentialsJSONRequest {

	String serviceProviderName = null;
	String identityProvider = null;
	String user = null;
	String password = null;
	String sessionSeconds = "3600";

	public String getServiceProviderName() {
		return serviceProviderName;
	}

	public void setServiceProviderName(String serviceProviderName) {
		this.serviceProviderName = serviceProviderName;
	}

	public String getIdentityProvider() {
		return identityProvider;
	}

	public void setIdentityProvider(String identityProvider) {
		this.identityProvider = identityProvider;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSessionSeconds() {
		return sessionSeconds;
	}

	public void setSessionSeconds(String sessionSeconds) {
		this.sessionSeconds = sessionSeconds;
	}
}
