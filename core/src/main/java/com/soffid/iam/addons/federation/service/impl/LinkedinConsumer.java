package com.soffid.iam.addons.federation.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.apis.LinkedInApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.ng.exception.InternalErrorException;

public class LinkedinConsumer extends OAuth2Consumer 
{

	static HashMap<String, Object> cfg = null;
	
	public LinkedinConsumer(FederationMember sp, FederationMember idp)
			throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		super(sp, idp);

		service = new ServiceBuilder(idp.getOauthKey())
				.apiSecret(idp.getOauthSecret().getPassword())
			    .scope("r_emailaddress r_basicprofile")
			    .state(secretState)
			    .callback(returnToUrl)
			    .build(LinkedInApi20.instance());

	}

	public boolean verifyResponse(Map<String,String> httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

	    // Now let's go and ask for a protected resource!
	    OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.linkedin.com/v1/people/~:(id,lastName,firstName,headline,picture-url,email-address)?format=json");
	    service.signRequest(accessToken, request);
	    Response response = service.execute(request);
	    
	    JSONObject m = new JSONObject(response.getBody());
	    
	    principal = m.optString("emailAddress", null);
	    if (principal == null || principal.trim().isEmpty())
	    	principal = m.optString("id");
	    
	    attributes.putAll(m.toMap());
	    attributes.put("EMAIL", m.optString("emailAddress"));
	    attributes.remove("emailAddress");
	    attributes.put("givenName",  m.optString("firstName"));
	    attributes.remove("firstName");
	    attributes.put("sn", m.optString("lastName"));
	    attributes.remove("lastName");
	    
	    

	    if (principal != null)
	    	return true;
	    else
	    	throw new InternalErrorException ("Cannot get linkedin profile");
	    
	}

}
