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

import org.mortbay.util.ajax.JSON;
import org.openid4java.consumer.ConsumerException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.oauth.OauthResponseAction;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class GoogleConsumer extends OAuth2Consumer 
{

	static HashMap<String, Object> cfg = null;
	
	public GoogleConsumer(FederationMember fm)
			throws ConsumerException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		super(fm);

		if (cfg == null)
		{
			URL cfgUrl = new URL("https://accounts.google.com/.well-known/openid-configuration");
			InputStream in = cfgUrl.openConnection().getInputStream();
			cfg = (HashMap<String, Object>) JSON.parse(new InputStreamReader(in, "UTF-8"), true);
		}

		service = new ServiceBuilder(fm.getOauthKey())
				.apiSecret(fm.getOauthSecret().getPassword())
			    .scope("email profile openid")
			    .state(secretState)
			    .callback(returnToUrl)
			    .build(GoogleApi20.instance());

	}

	public boolean verifyResponse(HttpServletRequest httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

		Map<String,String> r = (Map<String, String>) JSON.parse(accessToken.getRawResponse());
		String idToken = r.get("id_token");
		String[] split = idToken.split("\\.");
		
		String openIdB64 = split[1];
		while (openIdB64.length() % 4 != 0)
			openIdB64 += "=";
		String openIdToken = new String(Base64.decode(openIdB64));
		Map<String,String> m = (Map<String, String>) JSON.parse( openIdToken);
		
	    
	    attributes = new HashMap<String, Object>();
	    attributes.putAll(m);
	    attributes.put("givenName", m.get("given_name"));
	    attributes.remove("given_name");
	    attributes.put("sn", m.get("family_name"));
	    attributes.remove("family_name");
	    attributes.put("EMAIL", m.get("email"));
	    attributes.remove("email");
	    	
	    if (m.containsKey("email") && "true".equals (m.get("email_verified")) || Boolean.TRUE.equals(m.get("email_verified")))
	    {
	    	principal = m.get("email");
	    }
	    else
	    {
	    	principal = m.get("sub");
	    }
	    return true;
	}

}
