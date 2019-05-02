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
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class TokenHandler {
	HashMap<String, TokenInfo> authorizationCodes = new HashMap<String, TokenInfo>();
	HashMap<String, TokenInfo> tokens = new HashMap<String, TokenInfo>();
	LinkedList<TokenInfo> pendingTokens = new LinkedList<TokenInfo>();
	LinkedList<TokenInfo> activeTokens = new LinkedList<TokenInfo>();
	static TokenHandler instance;
	
	public static TokenHandler instance() {
		if (instance == null)
			instance = new TokenHandler();
		return instance;
	}
	
	public synchronized TokenInfo generateAuthenticationRequest ( OpenIdRequest request, String user)
	{
		expireTokens();
		
		TokenInfo t = new TokenInfo();
		t.setUser(user);
		t.setRequest(request);
		t.setAuthorizationCode( generateRandomString(36));
		t.created = System.currentTimeMillis();
		t.expires = t.created + 120000; // 2 Minutes to get token
		t.authentication = t.created;
		authorizationCodes.put(t.getAuthorizationCode(), t);
		pendingTokens.addLast(t);
		return t;
	}
	
	private void expireTokens() {
		long now = System.currentTimeMillis();
		for ( Iterator<TokenInfo> it = pendingTokens.iterator(); it.hasNext();) 
		{
			TokenInfo t = it.next();
			if (t.expires < now)
				it.remove();
		}
		for ( Iterator<TokenInfo> it = activeTokens.iterator(); it.hasNext();) 
		{
			TokenInfo t = it.next();
			if (t.expires < now)
				it.remove();
		}
	}

	private String generateRandomString (int length)
	{
		SecureRandom r = new SecureRandom();
		byte[] b = new byte[length];
		r.nextBytes(b);
		return Base64.encodeBytes(b,Base64.DONT_BREAK_LINES);
			
	}

	public TokenInfo getAuthorizationCode(String authorizationCode) 
	{
		return authorizationCodes.get(authorizationCode);
	}
	

	public synchronized void generateToken(TokenInfo t) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		if (t.getAuthorizationCode() != null)
		{
			authorizationCodes.remove(t.getAuthorizationCode());
			pendingTokens.remove(t);
		}
		t.token = generateRandomString(129);		
		t.refreshToken = generateRandomString(129);		
		Long timeOut = IdpConfig.getConfig().getFederationMember().getSessionTimeout();
		t.expires = System.currentTimeMillis() + (timeOut == null ? 600000 : timeOut.longValue() * 1000); // 10 minutes
		tokens.put(t.getToken(), t);
		activeTokens.addLast(t);
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

	public TokenInfo getToken(String token) {
		return tokens.get(token);
	}

	
}
