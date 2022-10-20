package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.AllowedScope;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class AuthorizationEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		IdpConfig config;
		OpenIdRequest r;
		try {
			config = IdpConfig.getConfig();
		
	    	req.getSession().setAttribute("soffid-session-type", "openid");
	    	r = new OpenIdRequest();
	    	
	    	r.setScope(req.getParameter("scope"));
	    	r.setClientId(req.getParameter("client_id"));
	    	r.setResponseType(req.getParameter("response_type"));
	    	r.setState(req.getParameter("state"));
	    	r.setNonce(req.getParameter("nonce"));
	    	r.setFederationMember( config.getFederationService().findFederationMemberByClientID(r.getClientId()) );
	    	r.setRedirectUrl(req.getParameter("redirect_uri"));
	    	r.setPkceAlgorithm(req.getParameter("code_challenge_method"));
	    	r.setPkceChallenge(req.getParameter("code_challenge"));
	    	if (r.getFederationMember() != null && r.getRedirectUrl() == null) {
	    		if (r.getFederationMember().getOpenidUrl() != null && !r.getFederationMember().getOpenidUrl().isEmpty())
	    		r.setRedirectUrl(r.getFederationMember().getOpenidUrl().iterator().next());
	    	}
	    	HttpSession session = req.getSession(true);
	    	if (r.getFederationMember() != null) {
		    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
	        	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, null);
	    	}	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
    	if ( ! checkParameters (r, resp))
    		return;
    	
    	try {
	    	if ( ! r.getFederationMember().getOpenidMechanism().contains( "IM" ) && 
	    		  r.getResponseType().contains("token"))
	    	{
	    		throw new ServletException("Not authorized to use implicit flow, requested response: "+r.getResponseType());
	    	}
	    	if ( ! r.getFederationMember().getOpenidMechanism().contains( "AC" ) && 
		    		  r.getResponseType().contains("code"))
	    	{
	    		throw new ServletException("Not authorized to use athorization code flow, requested response: "+r.getResponseType());
	    	}
	    	HttpSession session = req.getSession();
	    	session.setAttribute(SessionConstants.OPENID_REQUEST, r);
	    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
	    	
    		clientCredentialsGrantType(req, resp);
	    	
    	} catch (Exception e) {
            generateError(r, "server_error", e.toString(), resp);
		}
	}

	private void clientCredentialsGrantType(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException {
		String user = (String) req.getSession().getAttribute(SessionConstants.SEU_USER);
		if ("none".equals(req.getParameter("prompt")) && user != null) {
			AuthorizationResponse.generateResponse(getServletContext(), req, resp, "P", null);
			return;
		} 
		RequestDispatcher dispatcher = req.getRequestDispatcher(LoginServlet.URI);
		dispatcher.forward(req, resp);
	}


	private void generateError(OpenIdRequest r, String error, String description, HttpServletResponse resp) throws IOException {
		resp.sendRedirect(r.getRedirectUrl()+ (r.getRedirectUrl().contains("?") ? "&": "?") + "error="+error+"&error_description="+
				URLEncoder.encode(description, "UTF-8")+
				(r.getState() != null ? "&state="+r.getState(): ""));
	}

	private boolean checkParameters(OpenIdRequest r, HttpServletResponse resp) throws ServletException, IOException {
    	boolean found  = false;
    	if (r.getScope() != null) {
	    	for (String s: r.getScope().split(" +"))
	    	{
	    		if (s.equalsIgnoreCase("openid")) found = true;
	    	}
    	} else {
    		found = true;
    	}

    	if (! found)
    	{
            generateError(r, "invalid_scope", "The requested scope does not contain the scope openid: "+r.getScope(), resp);
            return false;
    	}
		
    	if (r.getFederationMember() == null)
    	{
            generateError(r, "unauthorized_client", "Unknown client id "+r.getClientId(), resp);
            return false;
    	}
    	
    	if (r.getScope() != null) {
	    	for (String s: r.getScope().split(" +")) {
	    		found = false;
	    		for (AllowedScope scope: r.getFederationMember().getAllowedScopes()) {
	    			if (scope.getScope().equals("*") || scope.getScope().equals(s)) {
	    				found = true; 
	    				break;
	    			}
	    		}
		    	if (!found) {
		    		generateError(r, "invalid_scope", "The requested scope "+s+" is not allowed due to system policies", resp);
		    		return false;
		    	}
	    	}
    	}
    	if (r.getResponseType() == null)
    	{
            generateError(r, "unsupported_response_type", "Wrong value for response_type: "+r.getResponseType(), resp);
            return false;
    	}
    	
    	if ( ! "code".equals( r.getResponseType()) && 
    			! "token".equals(r.getResponseType()) &&
    			! "id_token".equals(r.getResponseType()) &&
    			! "id_token token".equals(r.getResponseType()) &&
    			! "code id_token".equals(r.getResponseType()) &&
    			! "code token".equals(r.getResponseType()) &&
    			! "code id_token token".equals(r.getResponseType())
    			)
    	{
            generateError(r, "unsupported_response_type", "Wrong value for response_type: "+r.getResponseType(), resp);
            return false;
    	}


    	if (r.getRedirectUrl() == null)
    	{
            generateError(r, "invalid_request", "Missing redirect_uri", resp);
            return false;
    	}
    	boolean ok = false;
    	for (String url: r.getFederationMember().getOpenidUrl()) {
    		if (r.getRedirectUrl().equals(url) || r.getRedirectUrl().startsWith(url+"?")) 
    			ok = true;
    		if (url.endsWith("*") && r.getRedirectUrl().startsWith(url.substring(0, url.length()-1))) 
    			ok = true;
    	}
    	if (!ok) {
    		generateError(r, "invalid_request", "The requested return URL is not accepted "+r.getRedirectUrl(), resp);
    		return false;
    	}
    	
    	Set<String> mechs = r.getFederationMember().getOpenidMechanism();
    	if (! mechs.contains("IM") && ! mechs.contains("AC"))
    	{
            generateError(r, "unauthorized_client", "Client must use token endpoint with password grant_type", resp);
            return false;
    	}
    	return true;
	}
}
