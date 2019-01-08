package test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutionException;

import org.mortbay.util.ajax.JSON;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;

import es.caib.seycon.util.Base64;

public class OpenidTest {
	private final String clientId = "test2";
	private final String secret = "test2";
	final String secretState = "secret" + new Random().nextInt(999999999);
	public String accessTokenEndpoint = "https://bubu.soffid.com:2443/token";
	public String authorizationBaseUrl = "https://bubu.soffid.com:2443/authorization2";
	private String returnToUrl = "http://localhost/abc";
	
	public void implicitTest () throws IOException, InterruptedException, ExecutionException {
		ServiceBuilder serviceBuilder = new ServiceBuilder(clientId)
				.apiSecret(secret);
		

		OAuth20Service service = serviceBuilder.state(secretState)
			    .callback(returnToUrl)
			    .scope("openid")
			    .build( new CustomOAuthService());

		String s = service.getAuthorizationUrl();
		
		System.out.println(s);
		System.out.println("Access code: ");
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		String code =  in.readLine();
		System.out.println("State: ");
		String state = in.readLine();
		
		if (! secretState.equals(state))
		{
			System.err.println("State does not match");
		}
		else
		{
		    OAuth2AccessToken token = service.getAccessToken(code);
		    System.out.println("Token="+token.getAccessToken());
			Map<String,String> r = (Map<String, String>) JSON.parse(token.getRawResponse());
			String idToken = r.get("id_token");
			String[] split = idToken.split("\\.");
			
			String openIdB64 = split[1];
			while (openIdB64.length() % 4 != 0)
				openIdB64 += "=";
			String openIdToken = new String(Base64.decode(openIdB64));
			Map<String,Object> m = (Map<String, Object>) JSON.parse( openIdToken);
			for (String k: m.keySet())
			{
				System.out.println(k+"="+m.get(k));
			}
		}
		
		
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
	
	public static void main (String args[]) throws IOException, InterruptedException, ExecutionException
	{
		new OpenidTest().implicitTest();
	}

}
