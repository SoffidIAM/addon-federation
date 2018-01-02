package com.soffid.iam.addons.federation.rest.json;

import java.util.Map;

public class ParseSAMLResponseJSONRequest {

	Boolean autoProvision = null;
	Map<String, String> response = null;
	String protocol = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	String serviceProviderName = null;

	public String getServiceProviderName() {
		return serviceProviderName;
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
