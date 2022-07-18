package es.caib.seycon.idp.oauth.consumer;

import java.io.FileNotFoundException;
import java.io.IOException;
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

import com.github.scribejava.apis.FacebookApi;
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
	
	public FacebookConsumer(FederationMember fm)
			throws ConsumerException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		super(fm);

		service = new ServiceBuilder(fm.getOauthKey())
				.apiSecret(fm.getOauthSecret().getPassword())
			    .scope("email")
			    .state(secretState)
			    .callback(returnToUrl)
			    .build(FacebookApi.instance());

	}

	public boolean verifyResponse(HttpServletRequest httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

	    // Now let's go and ask for a protected resource!
	    OAuthRequest request = new OAuthRequest(Verb.GET, "https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,verified");
	    service.signRequest(accessToken, request);
	    Response response =  service.execute(request);
	    
	    JSONObject m =  (JSONObject) JSON.parse(response.getBody());
	    
	    attributes = new HashMap<String, Object>();
	    attributes.putAll(m.toMap());
	    attributes.put("givenName", m.get("first_name"));
	    attributes.remove("first_name");
	    attributes.put("sn", m.get("last_name"));
	    attributes.remove("last_name");
	    attributes.put("EMAIL", m.optString("email"));
	    attributes.remove("email");
	    	
	    if (m.has("email") && "true".equals (m.opt("verified")) || Boolean.TRUE.equals(m.opt("verified")))
	    {
	    	principal = m.getString("email");
	    }
	    else
	    {
	    	principal = m.getString("sub");
	    }
	    return true;
	    
	}

}
