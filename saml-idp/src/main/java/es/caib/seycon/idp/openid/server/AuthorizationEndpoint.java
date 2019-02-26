package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.SessionConstants;

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
	    	if (r.getFederationMember() != null)
	    		r.setRedirectUrl(r.getFederationMember().getOpenidUrl());
	    	HttpSession session = req.getSession(true);
	    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
        	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, null);
	    	
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
			throws ServletException, IOException {
		RequestDispatcher dispatcher = req.getRequestDispatcher(LoginServlet.URI);
		dispatcher.forward(req, resp);
	}


	private void generateError(OpenIdRequest r, String error, String description, HttpServletResponse resp) throws IOException {
		resp.sendRedirect(r.getRedirectUrl()+"?error="+error+"&error_description="+
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

    	
    	Set<String> mechs = r.getFederationMember().getOpenidMechanism();
    	if (! mechs.contains("IM") && ! mechs.contains("AC"))
    	{
            generateError(r, "unauthorized_client", "Client must use token endpoint with password grant_type", resp);
            return false;
    	}
    	return true;
	}
}
