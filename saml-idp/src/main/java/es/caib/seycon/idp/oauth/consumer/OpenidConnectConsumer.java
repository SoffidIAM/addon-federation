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

import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.oauth.OauthResponseAction;
import es.caib.seycon.ng.exception.InternalErrorException;

public class OpenidConnectConsumer extends OAuth2Consumer 
{

	HashMap<String, Object> cfg = null;
	public String accessTokenEndpoint;
	public String authorizationBaseUrl;
	
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
		{
			
		}
		else if (scope.getClass().isArray())
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
	
		accessTokenEndpoint = (String) cfg.get("token_endpoint");
		if (accessTokenEndpoint == null)
			throw new InternalErrorException("Missing token_endpoint member in "+fm.getName()+" metadata");
		
		authorizationBaseUrl = (String) cfg.get("authorization_endpoint");
		if (authorizationBaseUrl == null)
			throw new InternalErrorException("Missing authorization_endpoint member in "+fm.getName()+" metadata");

		serviceBuilder.state(secretState)
			    .callback(returnToUrl)
			    .build( new CustomOAuthService());

	}

	public boolean verifyResponse(HttpServletRequest httpReq) throws InternalErrorException, InterruptedException, ExecutionException, IOException  {
		OAuth2AccessToken accessToken = parseResponse(httpReq);

		String userInfo = (String) cfg.get("userinfo_endpoint");
	    // Now let's go and ask for a protected resource!
	    OAuthRequest request = new OAuthRequest(Verb.GET, userInfo);
	    service.signRequest(accessToken, request);
	    Response response = service.execute(request);
	    
	    Map<String,String> m =  (Map<String, String>) JSON.parse(response.getBody());
	    
	    System.out.println("NAME = "+m.get("name"));
	    System.out.println("EMAIL = "+m.get("email"));
	    
	    principal = m.get("email");
	    attributes.putAll(m);
	    attributes.put("givenName",  m.get("first_name"));
	    attributes.put("sn", m.get("last_name"));
	    
	    
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


