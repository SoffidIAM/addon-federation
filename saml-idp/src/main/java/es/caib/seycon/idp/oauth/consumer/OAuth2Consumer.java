package es.caib.seycon.idp.oauth.consumer;

import org.mortbay.util.ajax.JSON;
import org.openid4java.consumer.*;

import com.github.scribejava.core.model.OAuth1RequestToken;
import com.github.scribejava.core.model.OAuth2AccessToken;
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
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;

/**
 * Sample Consumer (Relying Party) implementation.
 */
public abstract class OAuth2Consumer implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String SESSION_ATTRIBUTE = "SoffidOAuthConsumer";

	public static OAuth2Consumer fromSesssion(HttpSession session) {
		return (OAuth2Consumer) session.getAttribute(SESSION_ATTRIBUTE);
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

	protected String email;
	protected String fullName;
	protected String lastName;
	protected String firstName;
	protected com.github.scribejava.core.oauth.OAuth20Service service;
	protected String returnToUrl;

	final String secretState = "secret" + new Random().nextInt(999999999);
	protected Map<String, Object> attributes = new HashMap<String, Object>();
	protected String principal;
	
	public OAuth2Consumer(FederationMember fm) throws ConsumerException,
			UnrecoverableKeyException, InvalidKeyException,
			FileNotFoundException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IllegalStateException,
			NoSuchProviderException, SignatureException, IOException,
			InternalErrorException {
		// instantiate a ConsumerManager object
		this.fm = fm;
		config = IdpConfig.getConfig();
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
    		String s = ((OAuth20Service) service).getAuthorizationUrl();
		    httpResp.sendRedirect(s);
	    } catch (Exception e) {
	    	System.out.println ("Error:" +e);
	    }
	    System.out.println("Got the Request Token!");
	    System.out.println();


	}

	public abstract boolean verifyResponse(HttpServletRequest httpReq) throws Exception  ;
	
	// --- processing the authentication response ---
	public OAuth2AccessToken parseResponse(HttpServletRequest httpReq) throws InternalErrorException, IOException, InterruptedException, ExecutionException  {
		
		String key = httpReq.getParameter("code");
		if (key == null)
		{
			String msg = httpReq.getParameter("error_message");
			if (msg == null)
				throw new InternalErrorException (msg == null ? "Internal authorization protocol error" : msg);
		}
		String secretState = httpReq.getParameter("state");
		if (secretState == null || ! secretState.equals(this.secretState))
		{
			throw new InternalErrorException ("Secret state does not match");
		}

	    return service.getAccessToken(key);
	}
	
	public String getRelyingParty()
	{
		return relyingParty;
	}

	public Map<String,Object> getAttributes() {
		return attributes;
	}

	public String getPrincipal() {
		return principal;
	}
}
