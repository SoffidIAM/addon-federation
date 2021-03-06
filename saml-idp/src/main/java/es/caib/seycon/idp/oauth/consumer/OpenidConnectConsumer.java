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

import org.mortbay.util.ajax.JSON;
import org.openid4java.consumer.ConsumerException;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class OpenidConnectConsumer extends OAuth2Consumer 
{

	HashMap<String, Object> cfg = null;
	public String accessTokenEndpoint;
	public String authorizationBaseUrl;
	private String userInfoEndpoint;
	
	public OpenidConnectConsumer(FederationMember fm)
			throws ConsumerException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException,
			KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		super(fm);

		cfg = (HashMap<String, Object>) JSON.parse(fm.getMetadades(), true);

		ServiceBuilder serviceBuilder = new ServiceBuilder(fm.getOauthKey())
				.apiSecret(fm.getOauthSecret().getPassword());
		
		Object scope = cfg.get("scope");
		if (scope == null)
			scope = cfg.get("supported_scopes");
		if (scope == null)
			scope = "openid";
		
		if (scope.getClass().isArray())
		{
			StringBuffer b = new StringBuffer();
			for ( Object s: (Object[]) scope)
			{
				if (s != null)
				{
					if (b.length() > 0) b.append(' ');
					b.append(s.toString());
				}
			}
			serviceBuilder.scope(b.toString());
		} else {
			serviceBuilder.scope(scope.toString());
		}

		for (String param: new String[] {"prompt", "display", "max_age", "ui_locales", "ui_hint"}) {
			if (cfg.get(param) != null) 
				params.put(param, (String) cfg.get(param));
		}

		accessTokenEndpoint = (String) cfg.get("token_endpoint");
		if (accessTokenEndpoint == null)
			throw new InternalErrorException("Missing token_endpoint member in "+fm.getName()+" metadata");
		
		authorizationBaseUrl = (String) cfg.get("authorization_endpoint");
		if (authorizationBaseUrl == null)
			throw new InternalErrorException("Missing authorization_endpoint member in "+fm.getName()+" metadata");

		userInfoEndpoint = (String) cfg.get("userinfo_endpoint");

		service = serviceBuilder.state(secretState)
			    .callback(returnToUrl)
			    .build( new CustomOAuthService());


	}

	public boolean verifyResponse(HttpServletRequest httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

		Map<String,String> r = (Map<String, String>) JSON.parse(accessToken.getRawResponse());
		String idToken = r.get("id_token");
		Map<String,String> m = new HashMap<String, String>();
		if (idToken != null)
		{
			String[] split = idToken.split("\\.");
			
			String openIdB64 = split[1];
			while (openIdB64.length() % 4 != 0)
				openIdB64 += "=";
			String openIdToken = new String(Base64.decode(openIdB64));
			m = (Map<String, String>) JSON.parse( openIdToken);
			if (userInfoEndpoint != null && ! userInfoEndpoint.isEmpty())
			{
			    OAuthRequest request = new OAuthRequest(Verb.GET, userInfoEndpoint);
			    service.signRequest(accessToken, request);
			    Response response =  service.execute(request);
			    
			    Map<String, String> m2 = (Map<String, String>) JSON.parse(response.getBody());
			    for (String k: m2.keySet())
			    	m.put(k, m2.get(k));
			}
		} 
		else if (userInfoEndpoint == null || userInfoEndpoint.isEmpty())
		{
			throw new IOException("Token does not contain an open ID Connect token, and no userinfo_endpoint specified");
		} else {
		    // Now let's go and ask for a protected resource!
		    OAuthRequest request = new OAuthRequest(Verb.GET, userInfoEndpoint);
		    service.signRequest(accessToken, request);
		    Response response =  service.execute(request);
		    
		    m =  (Map<String, String>) JSON.parse(response.getBody());

		}
		
	    
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

	class CustomOAuthService extends DefaultApi20 {
		@Override
		public String getAccessTokenEndpoint() {
			return accessTokenEndpoint;
		}

		@Override
		protected String getAuthorizationBaseUrl() {
			return authorizationBaseUrl;
		}
		
	}
}


