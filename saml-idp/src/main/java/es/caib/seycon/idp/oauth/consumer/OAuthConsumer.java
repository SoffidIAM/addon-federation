package es.caib.seycon.idp.oauth.consumer;

import org.openid4java.consumer.*;

import com.github.scribejava.core.model.OAuth1RequestToken;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.oauth.OAuth10aService;
import com.github.scribejava.core.oauth.OAuth20Service;
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
import java.util.concurrent.ExecutionException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;

/**
 * Sample Consumer (Relying Party) implementation.
 */
public abstract class OAuthConsumer implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String SESSION_ATTRIBUTE = "SoffidOAuthConsumer";

	public static OAuthConsumer fromSesssion(HttpSession session) {
		return (OAuthConsumer) session.getAttribute(SESSION_ATTRIBUTE);
	}

	public void store(HttpSession session) {
		session.setAttribute(SESSION_ATTRIBUTE, this);
	}
	
	

	OAuth1RequestToken requestToken;
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

	protected String email;
	protected String fullName;
	protected String lastName;
	protected String firstName;
	protected com.github.scribejava.core.oauth.OAuth10aService service;
	protected String returnToUrl;

	public OAuthConsumer(FederationMember fm) throws ConsumerException,
			UnrecoverableKeyException, InvalidKeyException,
			FileNotFoundException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException,
			InternalErrorException {
		// instantiate a ConsumerManager object
		this.fm = fm;
		returnToUrl = "https://" + config.getHostName() + ":"
				+ config.getStandardPort() + OauthResponseAction.URI;

	}

	// --- placing the authentication request ---
	public void authRequest(String userSuppliedString,
			HttpServletRequest httpReq, HttpServletResponse httpResp) throws IOException
	 {
		relyingParty = userSuppliedString;

	    requestToken = null;
	    try {
	    	requestToken = service.getRequestToken();
		    httpResp.sendRedirect(service.getAuthorizationUrl(requestToken));
	    } catch (Exception e) {
	    	System.out.println ("Error:" +e);
	    }
	    System.out.println("Got the Request Token!");
	    System.out.println();


	}

	public abstract String verifyResponse(HttpServletRequest httpReq) throws InternalErrorException  ;
	
	// --- processing the authentication response ---
	public Token parseResponse(HttpServletRequest httpReq) throws InternalErrorException, IOException, InterruptedException, ExecutionException  {
		
		String key = httpReq.getParameter("code");
		if (key == null)
		{
			String msg = httpReq.getParameter("error_message");
			if (msg == null)
				throw new InternalErrorException (msg == null ? "Internal authorization protocol error" : msg);
		}
	    return service.getAccessToken(requestToken, key);
	}
	
	public String getRelyingParty()
	{
		return relyingParty;
	}
}
