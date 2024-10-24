package es.caib.seycon.idp.openid.server;

import java.util.HashSet;

import com.soffid.iam.addons.federation.api.TokenType;
import com.soffid.iam.addons.federation.common.FederationMember;

public class OpenIdRequest {
	TokenType type;
   	String scope ;
	String clientId ;
	String responseType ;
	String redirectUrl ;
	String state;
	String nonce;
	String display;
	String prompt;
	String maxAge;
	String uiLocales;
	String idTokenHint;
	String loginHint;
	String acrValues;
	String pkceChallenge;
	String pkceAlgorithm;
	FederationMember federationMember;
	private HashSet<String> responseTypeSet;
	
	public String toString() {
		return "[Type: "+type+" Scope: "+scope+", ClientId: "+clientId+", ResponseType: "+responseType+", RedirectURL: "+redirectUrl+
				", State: "+state+", Nonce: "+nonce+", Display: "+display+", Prompt: "+prompt+", MaxAge: "+maxAge
				+", uiLocales: "+uiLocales+", IdTokenHint: "+idTokenHint+", LoginHint: "+loginHint+", acrValues:"+acrValues+
				", PkceChallenge: "+pkceChallenge+", PkceAlgorithm: "+pkceAlgorithm+"]";
	}
	

	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getResponseType() {
		return responseType;
	}
	public void setResponseType(String responseType) {
		this.responseType = responseType;
		responseTypeSet = new HashSet<String>();
		for (String s: responseType.split(" +"))
		{
			responseTypeSet.add(s);
		}
	}
	public String getRedirectUrl() {
		return redirectUrl;
	}
	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}
	public String getState() {
		return state;
	}
	public void setState(String state) {
		this.state = state;
	}
	public String getNonce() {
		return nonce;
	}
	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
	public String getDisplay() {
		return display;
	}
	public void setDisplay(String display) {
		this.display = display;
	}
	public String getPrompt() {
		return prompt;
	}
	public void setPrompt(String prompt) {
		this.prompt = prompt;
	}
	public String getMaxAge() {
		return maxAge;
	}
	public void setMaxAge(String maxAge) {
		this.maxAge = maxAge;
	}
	public String getUiLocales() {
		return uiLocales;
	}
	public void setUiLocales(String uiLocales) {
		this.uiLocales = uiLocales;
	}
	public String getIdTokenHint() {
		return idTokenHint;
	}
	public void setIdTokenHint(String idTokenHint) {
		this.idTokenHint = idTokenHint;
	}
	public String getLoginHint() {
		return loginHint;
	}
	public void setLoginHint(String loginHint) {
		this.loginHint = loginHint;
	}
	public String getAcrValues() {
		return acrValues;
	}
	public void setAcrValues(String acrValues) {
		this.acrValues = acrValues;
	}
	public FederationMember getFederationMember() {
		return federationMember;
	}
	public void setFederationMember(FederationMember federationMember) {
		this.federationMember = federationMember;
	}
	public HashSet<String> getResponseTypeSet() {
		return responseTypeSet;
	}
	public void setResponseTypeSet(HashSet<String> responseTypeSet) {
		this.responseTypeSet = responseTypeSet;
	}


	public String getPkceChallenge() {
		return pkceChallenge;
	}


	public void setPkceChallenge(String pkceChallenge) {
		this.pkceChallenge = pkceChallenge;
	}


	public String getPkceAlgorithm() {
		return pkceAlgorithm;
	}


	public void setPkceAlgorithm(String pkceAlgorithm) {
		this.pkceAlgorithm = pkceAlgorithm;
	}


	public void setType(TokenType type) {
		this.type = type;
		
	}


	public TokenType getType() {
		return type;
	}
}
