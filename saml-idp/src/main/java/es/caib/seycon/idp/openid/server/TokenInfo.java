package es.caib.seycon.idp.openid.server;

import java.util.Map;

public class TokenInfo {
	String token;
	String refreshToken;
	String authorizationCode;
	String user;
	OpenIdRequest request;
	long created;
	long expires;
	long expiresRefresh;
	long authentication;
	private String authenticationMethod;
	Long sessionId;
	String sessionKey;
	
	public String toString() {
		return "[Token: "+token+", RefreshToken: "+refreshToken+", AuthorizationCode: "+authorizationCode
				+", User: "+user+", AuthenticationMethod: "+authentication+", SessionId: "+sessionId
				+", SessionKey: "+sessionKey+", Request: "+request.toString()+"]";
	}
	
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public OpenIdRequest getRequest() {
		return request;
	}
	public void setRequest(OpenIdRequest request) {
		this.request = request;
	}
	public long getCreated() {
		return created;
	}
	public void setCreated(long created) {
		this.created = created;
	}
	public long getExpires() {
		return expires;
	}
	public void setExpires(long expires) {
		this.expires = expires;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public String getAuthorizationCode() {
		return authorizationCode;
	}
	public void setAuthorizationCode(String authorizationCode) {
		this.authorizationCode = authorizationCode;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public long getAuthentication() {
		return authentication;
	}
	public void setAuthentication(long authentication) {
		this.authentication = authentication;
	}
	public String getAuthenticationMethod() {
		return authenticationMethod;
	}
	public void setAuthenticationMethod(String authenticationMethod) {
		this.authenticationMethod = authenticationMethod;
	}
	public Long getSessionId() {
		return sessionId;
	}
	public void setSessionId(Long sessionId) {
		this.sessionId = sessionId;
	}
	public String getSessionKey() {
		return sessionKey;
	}
	public void setSessionKey(String sessionKey) {
		this.sessionKey = sessionKey;
	}

	public long getExpiresRefresh() {
		return expiresRefresh;
	}

	public void setExpiresRefresh(long expriresRefresh) {
		this.expiresRefresh = expriresRefresh;
	}
	
	boolean isExpired() {
		return System.currentTimeMillis() > expires;
	}

	boolean isRefreshExpired() {
		return System.currentTimeMillis() > expiresRefresh;
	}
}
