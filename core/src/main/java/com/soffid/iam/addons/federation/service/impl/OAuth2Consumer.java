package com.soffid.iam.addons.federation.service.impl;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.concurrent.ExecutionException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.opensaml.saml.common.xml.SAMLConstants;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.SamlRequest;

import es.caib.seycon.ng.exception.InternalErrorException;

/**
 * Sample Consumer (Relying Party) implementation.
 */
public abstract class OAuth2Consumer implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static Map<String, OAuth2Consumer> consumers = new Hashtable<String, OAuth2Consumer>();
	long created = System.currentTimeMillis();
	
	public static OAuth2Consumer fromRequest(Map<String,String> request) {
		String secret = request.get("state");
		if (secret == null)
			return null;
		
		long timeout = System.currentTimeMillis() - 1000 * 60 * 30; // 30 minutes to get login
		synchronized (consumers)
		{
			for (Iterator<Entry<String, OAuth2Consumer>> it = consumers.entrySet().iterator(); it.hasNext();)
			{
				Entry<String, OAuth2Consumer> entry = it.next();
				if (entry.getValue().created < timeout)
					it.remove();
			}
		}
		OAuth2Consumer consumer = consumers.get(secret);
		return consumer;
	}


	Token requestToken;
	FederationMember idp;
	
	public String getEmail() {
		return email;
	}

	public String getFullName() {
		return fullName;
	}

	public String getLastName() {
		return lastName;
	}

	public String getFirstName() {
		return firstName;
	}

	protected String email;
	protected String fullName;
	protected String lastName;
	protected String firstName;
	protected com.github.scribejava.core.oauth.OAuth20Service service;
	protected String returnToUrl;

	String secretState = null;
	protected Map<String, Object> attributes = new HashMap<String, Object>();
	protected String principal;
	private FederationMember sp;
	
	public OAuth2Consumer(FederationMember sp, FederationMember idp) throws 
			UnrecoverableKeyException, InvalidKeyException,
			FileNotFoundException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException,
			InternalErrorException {
		// instantiate a ConsumerManager object
		this.idp = idp;
		this.sp = sp;

		returnToUrl = sp.getOpenidUrl();

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        Hex encoder = new Hex();
        final byte[] buf = new byte[24];
        random.nextBytes(buf);
        secretState = "_" + StringUtils.newStringUsAscii(encoder.encode(buf));
	}

	// --- placing the authentication request ---
	public void authRequest(SamlRequest req) throws IOException
	 {
	    requestToken = null;
	    try {
    		String s = ((OAuth20Service) service).getAuthorizationUrl();
    		req.setMethod(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    		req.setUrl(s);
    		consumers.put(secretState, this);
	    } catch (Exception e) {
	    	System.out.println ("Error:" +e);
	    }
	}

	public abstract boolean verifyResponse(Map<String,String> request) throws Exception  ;
	
	// --- processing the authentication response ---
	public OAuth2AccessToken parseResponse(Map<String,String> request) throws InternalErrorException, IOException, InterruptedException, ExecutionException  {
		
		String key = request.get("code");
		if (key == null)
		{
			String msg = request.get("error_message");
			if (msg == null)
				throw new InternalErrorException (msg == null ? "Internal authorization protocol error" : msg);
		}
		String secretState = request.get("state");
		if (secretState == null || ! secretState.equals(this.secretState))
		{
			throw new InternalErrorException ("Secret state does not match");
		}

	    return service.getAccessToken(key);
	}
	
	public Map<String,Object> getAttributes() {
		return attributes;
	}

	public String getPrincipal() {
		return principal;
	}

	public FederationMember getIdp() {
		return idp;
	}

	public FederationMember getSp() {
		return sp;
	}
}
