package es.caib.seycon.idp.openid.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.algorithms.Algorithm;
import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Session;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.SessionService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class TokenHandler {
	HashMap<String, TokenInfo> authorizationCodes = new HashMap<String, TokenInfo>();
	HashMap<String, TokenInfo> refreshTokens = new HashMap<String, TokenInfo>();
	HashMap<String, TokenInfo> tokens = new HashMap<String, TokenInfo>();
	LinkedList<TokenInfo> pendingTokens = new LinkedList<TokenInfo>();
	LinkedList<TokenInfo> activeTokens = new LinkedList<TokenInfo>();
	static TokenHandler instance;
	
	public static TokenHandler instance() {
		if (instance == null)
			instance = new TokenHandler();
		return instance;
	}
	
	public synchronized TokenInfo generateAuthenticationRequest ( OpenIdRequest request, String user, String authType) throws InternalErrorException
	{
		expireTokens();
		
		TokenInfo t = new TokenInfo();
		t.setUser(user);
		t.setRequest(request);
		t.setAuthorizationCode( generateRandomString(36));
		t.created = System.currentTimeMillis();
		t.expires = t.created + 120000; // 2 Minutes to get token
		t.authentication = t.created;
		t.setAuthenticationMethod(authType);
		authorizationCodes.put(t.getAuthorizationCode(), t);
		pendingTokens.addLast(t);
		
		getFederationService().createOauthToken(generateOauthToken(t));
		return t;
	}
	
	private void expireTokens() throws InternalErrorException {
		long now = System.currentTimeMillis();
		for ( Iterator<TokenInfo> it = pendingTokens.iterator(); it.hasNext();) 
		{
			TokenInfo t = it.next();
			if (t.isExpired()) {
				getFederationService().deleteOauthToken(generateOauthToken(t));
				it.remove();
			}
		}
		for ( Iterator<TokenInfo> it = activeTokens.iterator(); it.hasNext();) 
		{
			TokenInfo t = it.next();
			if (t.isExpired() && t.isRefreshExpired()) {
				if (t.getRefreshToken() != null)
					refreshTokens.remove(t.getRefreshToken());
				getFederationService().deleteOauthToken(generateOauthToken(t));
				it.remove();
			}
		}
	}

	private String generateRandomString (int length)
	{
		SecureRandom r = new SecureRandom();
		byte[] b = new byte[length];
		r.nextBytes(b);
		return Base64.encodeBytes(b,Base64.DONT_BREAK_LINES);
			
	}

	public TokenInfo getAuthorizationCode(String authorizationCode) throws InternalErrorException 
	{
		expireTokens();
		TokenInfo ti = authorizationCodes.get(authorizationCode);
		if (ti == null) {
			OauthToken o = getFederationService().findOauthTokenByAuthorizationCode(getIdentityProvider(), authorizationCode);
			if (o != null)
				ti = parseOauthToken(o);
		}
		if (ti == null || ti.isExpired())
			return null;
		else
			return ti;
	}
	
	public TokenInfo getRefreshToken(String refreshToken) throws InternalErrorException 
	{
		expireTokens();
		TokenInfo ti = refreshTokens.get(refreshToken);
		if (ti == null) {
			OauthToken o = getFederationService().findOauthTokenByRefreshToken(getIdentityProvider(), refreshToken);
			if (o != null)
				ti = parseOauthToken(o);
		}
		if (ti == null || ti.isRefreshExpired())
			return null;
		else
			return ti;
	}

	public synchronized void generateToken(TokenInfo t) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		if (t.getAuthorizationCode() != null)
		{
			authorizationCodes.remove(t.getAuthorizationCode());
			pendingTokens.remove(t);
		}
		getFederationService().deleteOauthToken(generateOauthToken(t));
		t.token = generateRandomString(129);		
		t.authorizationCode = null;
		t.refreshToken = generateRandomString(129);		
		refreshTokens.put(t.refreshToken, t);
		Long timeOut = IdpConfig.getConfig().getFederationMember().getSessionTimeout();
		t.expires = System.currentTimeMillis() + (timeOut == null ? 600000 : timeOut.longValue() * 1000); // 10 minutes
		Long refreshTimeout = t.request.getFederationMember().getOauthSessionTimeout();
		if (refreshTimeout == null)
			refreshTimeout = IdpConfig.getConfig().getFederationMember().getOauthSessionTimeout();
		if (refreshTimeout == null)
			t.expiresRefresh = System.currentTimeMillis() + 24L * 60 * 60 * 1000L; // 1 day
		else
			t.expiresRefresh = System.currentTimeMillis() + refreshTimeout.longValue() * 1000L;
		tokens.put(t.getToken(), t);
		activeTokens.addLast(t);
		getFederationService().createOauthToken(generateOauthToken(t));
	}

	public synchronized void renewToken(TokenInfo t) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		if (t.getAuthorizationCode() != null)
		{
			authorizationCodes.remove(t.getAuthorizationCode());
			pendingTokens.remove(t);
		}
		if (t.refreshToken != null) 
			refreshTokens.remove(t.refreshToken);
		tokens.remove(t.token);
		
		getFederationService().deleteOauthToken(generateOauthToken(t));

		t.authorizationCode = null;
		t.token = generateRandomString(129);		
		t.refreshToken = generateRandomString(129);		
		Long timeOut = IdpConfig.getConfig().getFederationMember().getSessionTimeout();
		t.expires = System.currentTimeMillis() + (timeOut == null ? 600000 : timeOut.longValue() * 1000); // 10 minutes
		refreshTokens.put(t.refreshToken, t);
		tokens.put(t.getToken(), t);
		activeTokens.addLast(t);

		getFederationService().createOauthToken(generateOauthToken(t));
	}

	public String generateIdToken(TokenInfo t, Map<String, Object> att) throws JSONException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		IdpConfig c = IdpConfig.getConfig();
		JSONObject o = new JSONObject();
		o.put("auth_time", t.getAuthentication());
		o.put("nonce", t.request.getNonce());

		Builder builder = JWT.create().withAudience(t.request.getFederationMember().getOpenidClientId())
				.withExpiresAt( new Date (t.getExpires()))
				.withIssuedAt(new Date(t.getCreated()))
				.withClaim("auth_time", t.getAuthentication())
				.withClaim("nonce", t.request.getNonce())
				.withKeyId(c.getHostName())
				.withIssuer("https://"+c.getHostName()+":"+c.getStandardPort());

		String subject = null;
		String email = null;
		String uid = null;
		for (String openIdName: att.keySet())
		{
			Object value = att.get(openIdName);
			if (value != null)
			{
				List<Object> values = new LinkedList();
				if (value instanceof Collection)
					values.addAll((Collection) value);
				else
					values.add(value);
					
				if ( openIdName.equals("uid") && !values.isEmpty())
					uid = values.iterator().next().toString();
				if ( openIdName.equals("sub") && !values.isEmpty())
					subject = values.iterator().next().toString();
				if ( openIdName.equalsIgnoreCase("email") && !values.isEmpty())
					email = values.iterator().next().toString();
				
				if (values.size() == 1)
				{
					value = values.iterator().next();
					if (value != null)
					{
						if (value instanceof Long)
							builder.withClaim(openIdName, (Long)value);
						else if (value instanceof Integer)
							builder.withClaim(openIdName, (Integer)value);
						else if (value instanceof Date)
							builder.withClaim(openIdName, (Date)value);
						else if (value instanceof Double)
							builder.withClaim(openIdName, (Double)value);
						else if (value instanceof Boolean)
							builder.withClaim(openIdName, (Boolean)value);
						else
							builder.withClaim(openIdName, value.toString());
					}
				}
				else
				{
					String[] data = new String[values.size()];
					int i = 0;
					for ( Object obj: values)
						data[i++] = obj.toString();
					builder.withArrayClaim(openIdName, data);
				}
			}
		}
		
		if (subject == null)
		{
			if (uid != null)
				builder.withSubject(uid);
			if (email != null)
				builder.withSubject(email);
		}

		KeyPair keyPair = c.getKeyPair();
		
		Algorithm algorithmRS = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
		String signedToken = builder.sign(algorithmRS);
		
		return signedToken;
	}

	public TokenInfo getToken(String token) throws InternalErrorException {
		TokenInfo ti = tokens.get(token);
		if (ti == null) {
			OauthToken o = getFederationService().findOauthTokenByToken(getIdentityProvider(), token);
			if (o != null)
				ti = parseOauthToken(o);
		}
		if (ti == null || ti.isExpired())
			return null;
		else
			return ti;
	}

	private String getIdentityProvider()  {
		try {
			return IdpConfig.getConfig().getPublicId();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private FederationService getFederationService()  {
		try {
			return IdpConfig.getConfig().getFederationService();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	protected OauthToken generateOauthToken (TokenInfo t)  {
		OauthToken o = new OauthToken();
		o.setAuthenticated(new Date(t.authentication));
		o.setAuthenticationMethod(t.getAuthenticationMethod());
		o.setAuthorizationCode(t.getAuthorizationCode());
		o.setCreated(new Date(t.getCreated()));
		o.setExpires(new Date(t.getExpires()));
		o.setRefreshExpires(new Date(t.getExpiresRefresh()));
		o.setIdentityProvider(getIdentityProvider());
		o.setRefreshToken(t.getRefreshToken());
		o.setServiceProvider(t.getRequest().getFederationMember().getPublicId());
		o.setToken(t.getToken());
		o.setUser(t.getUser());
		o.setSessionId(t.getSessionId());
		o.setSessionKey(t.getSessionKey());
		return o;
	}
	
	protected TokenInfo parseOauthToken (OauthToken o) throws InternalErrorException  {
		TokenInfo t = new TokenInfo();
		t.setAuthentication(o.getAuthenticated().getTime());
		t.setAuthenticationMethod(o.getAuthenticationMethod());
		t.setAuthorizationCode(o.getAuthorizationCode());
		t.setCreated(o.getCreated().getTime());
		t.setExpires(o.getExpires().getTime());
		t.setExpiresRefresh(o.getRefreshExpires().getTime());
		t.setRefreshToken(o.getRefreshToken());
		t.setRequest(new OpenIdRequest());
		t.getRequest().setFederationMember(getFederationService().findFederationMemberByPublicId(o.getServiceProvider()));
		t.setToken(o.getToken());
		t.setUser(o.getUser());
		t.setSessionId(o.getSessionId());
		t.setSessionKey(o.getSessionKey());
		return t;
	}

	public void revoke(TokenInfo t) throws InternalErrorException, IOException {
		if (t.getAuthorizationCode() != null)
		{
			authorizationCodes.remove(t.getAuthorizationCode());
			pendingTokens.remove(t);
		}
		if (t.refreshToken != null) 
			refreshTokens.remove(t.refreshToken);
		tokens.remove(t.token);
		
		getFederationService().deleteOauthToken(generateOauthToken(t));

		if (t.getSessionId() != null) {
			SessionService sessionService = new RemoteServiceLocator().getSessionService();
			Session session = sessionService.getSession(t.getSessionId(), t.getSessionKey());
			if (session != null)
				sessionService.destroySession(session);
		}
	}

	public void setSession(TokenInfo t, Session session) throws InternalErrorException, IOException {
		if (t.getSessionId() != null) {
			SessionService sessionService = new RemoteServiceLocator().getSessionService();
			Session oldSession = sessionService.getSession(t.getSessionId(), t.getSessionKey());
			if (oldSession != null)
				sessionService.destroySession(oldSession);
		}
		t.setSessionId(session.getId());
		t.setSessionKey(session.getKey());
		
		getFederationService().updateOauthToken(generateOauthToken(t));
	}
}

