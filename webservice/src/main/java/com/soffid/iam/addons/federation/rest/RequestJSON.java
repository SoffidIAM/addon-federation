package com.soffid.iam.addons.federation.rest;

import java.util.Map;

public class RequestJSON {

	// validate-domain
	String domain = null;
	
	// validate-credentials
	String serviceProviderName = null;
	String identityProvider = null;
	String user = null;
	String password = null;
	String sessionSeconds = "3600";
	
	// generateSAMLRequest
//	String serviceProviderName = null;
//	String identityProvider = null;
//	String user = null;
//	String sessionSeconds = null;
	
	// parseSAMLResponse
	Boolean autoProvision = null;
	Map<String, String> response = null;
	String protocol = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
//	String serviceProviderName = null;
	

	public String getDomain() {
		return domain;
	}
	
	public void setDomain(String domain) {
		this.domain = domain;
	}
	
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
	
	public Boolean getAutoProvision() {
		return autoProvision;
	}
	
	public void setAutoProvision(Boolean autoProvision) {
		this.autoProvision = autoProvision;
	}
	
	public Map<String, String> getResponse() {
		return response;
	}
	
	public void setResponse(Map<String, String> response) {
		this.response = response;
	}
	
	public String getProtocol() {
		return protocol;
	}
	
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
}
