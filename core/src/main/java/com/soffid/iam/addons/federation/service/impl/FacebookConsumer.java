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

import com.github.scribejava.apis.FacebookApi;
import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.ng.exception.InternalErrorException;

public class FacebookConsumer extends OAuth2Consumer 
{

	static HashMap<String, Object> cfg = null;
	
	public FacebookConsumer(FederationMember sp, FederationMember idp)
			throws  UnrecoverableKeyException, InvalidKeyException, FileNotFoundException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		super(sp, idp);

		service = new ServiceBuilder(idp.getOauthKey())
				.apiSecret(idp.getOauthSecret().getPassword())
			    .scope("email")
			    .state(secretState)
			    .callback(returnToUrl)
			    .build(FacebookApi.instance());

	}

	public boolean verifyResponse(Map<String,String> httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

	    // Now let's go and ask for a protected resource!
	    OAuthRequest request = new OAuthRequest(Verb.GET, "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,verified");
	    service.signRequest(accessToken, request);
	    Response response =  service.execute(request);
	    
	    JSONObject m =  new JSONObject(response.getBody());
	    
	    attributes = new HashMap<String, Object>();
	    attributes.putAll(m.toMap());
	    attributes.put("givenName", m.getString("first_name"));
	    attributes.remove("first_name");
	    attributes.put("sn", m.get("last_name"));
	    attributes.remove("last_name");
	    attributes.put("EMAIL", m.optString("email"));
	    attributes.remove("email");
	    	
	    if (m.has("email") && "true".equals (m.opt("verified")) || Boolean.TRUE.equals(m.opt("verified")))
	    {
	    	principal = (String) m.getString("email");
	    }
	    else
	    {
	    	principal = (String) m.getString("sub");
	    }
	    return true;
	    
	}

}
