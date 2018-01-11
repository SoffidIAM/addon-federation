package com.soffid.iam.addons.federation.rest.json;

public class GenerateSAMLLogoutRequestJSON {

	String serviceProviderName = null;
	String identityProvider = null;
	String user = null;
	boolean force = false;
	boolean backChannel = false;

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

	public boolean isForce() {
		return force;
	}

	public void setForce(boolean force) {
		this.force = force;
	}

	public boolean isBackChannel() {
		return backChannel;
	}

	public void setBackChannel(boolean backChannel) {
		this.backChannel = backChannel;
	}
}
