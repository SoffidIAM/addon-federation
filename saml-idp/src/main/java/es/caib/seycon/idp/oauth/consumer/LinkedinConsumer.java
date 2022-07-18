package es.caib.seycon.idp.oauth.consumer;

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
import org.mortbay.util.ajax.JSON;
import org.openid4java.consumer.ConsumerException;

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.apis.LinkedInApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.oauth.OauthResponseAction;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LinkedinConsumer extends OAuth2Consumer 
{

	static HashMap<String, Object> cfg = null;
	
	public LinkedinConsumer(FederationMember fm)
			throws ConsumerException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		super(fm);

		service = new ServiceBuilder(fm.getOauthKey())
				.apiSecret(fm.getOauthSecret().getPassword())
			    .scope("r_emailaddress r_basicprofile")
			    .state(secretState)
			    .callback(returnToUrl)
			    .build(LinkedInApi20.instance());

	}

	public boolean verifyResponse(HttpServletRequest httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

	    // Now let's go and ask for a protected resource!
	    OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.linkedin.com/v1/people/~:(id,lastName,firstName,headline,picture-url,email-address)?format=json");
	    service.signRequest(accessToken, request);
	    Response response = service.execute(request);
	    
	    JSONObject m =  (JSONObject) JSON.parse(response.getBody());
	    
	    principal = m.optString("emailAddress");
	    if (principal == null)
	    	principal = m.getString("id");
	    
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
