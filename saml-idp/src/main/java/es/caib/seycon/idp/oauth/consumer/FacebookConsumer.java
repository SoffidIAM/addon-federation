package es.caib.seycon.idp.oauth.consumer;

import org.mortbay.util.ajax.JSON;
import org.openid4java.consumer.*;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.FacebookApi;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.oauth.OauthResponseAction;
import es.caib.seycon.ng.exception.InternalErrorException;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;

/**
 * Sample Consumer (Relying Party) implementation.
 */
public class FacebookConsumer implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String SESSION_ATTRIBUTE = "SoffidOAuthConsumer";

	public static FacebookConsumer fromSesssion(HttpSession session) {
		return (FacebookConsumer) session.getAttribute(SESSION_ATTRIBUTE);
	}

	public void store(HttpSession session) {
		session.setAttribute(SESSION_ATTRIBUTE, this);
	}
	
	

	Token requestToken;
	FederationMember fm;
	IdpConfig config;
	String relyingParty;
	
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

	private String email;
	private String fullName;
	private String lastName;
	private String firstName;
	private OAuthService service;

	public FacebookConsumer(FederationMember fm) throws ConsumerException,
			UnrecoverableKeyException, InvalidKeyException,
			FileNotFoundException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException,
			InternalErrorException {
		// instantiate a ConsumerManager object
		this.fm = fm;
		config = IdpConfig.getConfig();

		String returnToUrl = "https://" + config.getHostName() + ":"
				+ config.getStandardPort() + OauthResponseAction.URI;


		service = new ServiceBuilder()
		    .provider(FacebookApi.class)
		    .apiKey(config.getFacebookKey())
		    .apiSecret(config.getFacebookSecret())
		    .callback(returnToUrl)
		    .scope("email")
		    .build();

	}

	// --- placing the authentication request ---
	public void authRequest(String userSuppliedString,
			HttpServletRequest httpReq, HttpServletResponse httpResp) throws IOException
	 {
		relyingParty = userSuppliedString;

	    requestToken = null;
	    try {
	    	requestToken = service.getRequestToken();
	    } catch (Exception e) {
	    	System.out.println ("Error:" +e);
	    }
	    System.out.println("Got the Request Token!");
	    System.out.println();

	    httpResp.sendRedirect(service.getAuthorizationUrl(requestToken));

	}

	// --- processing the authentication response ---
	public String verifyResponse(HttpServletRequest httpReq) throws InternalErrorException  {
		
		String key = httpReq.getParameter("code");
		if (key == null)
		{
			String msg = httpReq.getParameter("error_message");
			if (msg == null)
				throw new InternalErrorException (msg == null ? "Internal authorization protocol error" : msg);
		}
	    Verifier verifier = new Verifier(key);

	    Token accessToken = service.getAccessToken(requestToken, verifier);

	    // Now let's go and ask for a protected resource!
	    OAuthRequest request = new OAuthRequest(Verb.GET, "https://graph.facebook.com/me");
	    service.signRequest(accessToken, request);
	    Response response = request.send();
	    
	    Map<String,String> m =  (Map<String, String>) JSON.parse(response.getBody());
	    
	    System.out.println("NAME = "+m.get("name"));
	    System.out.println("EMAIL = "+m.get("email"));
	    
	    String username = m.get("username");
	    firstName = m.get("first_name");
	    lastName = m.get("last_name");
	    fullName = m.get("name");
	    email = m.get("email");
	    
	    
	    if ("true".equals (m.get("verified")) || Boolean.TRUE.equals(m.get("verified")))
	    	return "facebook:"+username;
	    else
	    	throw new InternalErrorException ("Your email address is not verified by Facebook");
	    
	}
	
	public String getRelyingParty()
	{
		return relyingParty;
	}
}
