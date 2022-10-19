package es.caib.seycon.idp.openid.server;

import java.util.Map;

import com.soffid.iam.addons.federation.api.TokenType;

public class TokenInfo {
	String token;
	String refreshToken;
	String authorizationCode;
	String user;
	OpenIdRequest request;
	long lastUse;
	long created;
	long expires;
	long expiresRefresh;
	long authentication;
	private String authenticationMethod;
	Long sessionId;
	String sessionKey;
	String jwtId;
	String scope;
	String pkceChallenge;
	String pkceAlgorithm;
	private TokenType type;
	public String refreshTokenFull;
	public String oauthSessionId;
	
	public String toString() {
		return "[Token: "+token+", RefreshToken: "+refreshToken+", AuthorizationCode: "+authorizationCode
				+", User: "+user+", AuthenticationMethod: "+authentication+", SessionId: "+sessionId
				+", SessionKey: "+sessionKey+", Request: "+request.toString()+", Scope: "+request.getScope()+
				", PkceChallenge: "+pkceChallenge+", PkceAlgorithm: "+pkceAlgorithm+"]";
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
	public TokenInfo() {
		super();
		updateLastUse();
	}

	public void updateLastUse() {
		lastUse = System.currentTimeMillis();
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

	public long getLastUse() {
		return lastUse;
	}

	public void setLastUse(long lastUse) {
		this.lastUse = lastUse;
	}

	public boolean isNotUsed() {
		return System.currentTimeMillis() > lastUse + 900_000; // 15 minutes
	}

	public String getJwtId() {
		return jwtId;
	}

	public void setJwtId(String jwtId) {
		this.jwtId = jwtId;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
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

	public String getOauthSessionId() {
		return oauthSessionId;
	}

	public void setOauthSessionId(String oauthSessionId) {
		this.oauthSessionId = oauthSessionId;
	}
}
