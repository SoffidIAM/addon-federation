package es.caib.seycon.idp.openid.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.exception.InternalErrorException;

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
		FederationMember fm;
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
	    	
	    	HttpSession session = req.getSession(true);
	    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
        	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, null);
	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
    	checkParameters (r);
    	if ( "implicit".equals( r.getFederationMember().getOpenidFlow()) )
    	{
    		try {
    			implicitFlow (r, req, resp);
			} catch (Exception e) {
				throw new ServletException("Error processing authentication request", e);
			}
    	} else {
    		try {
				authorizationFlow (r, req, resp);
			} catch (Exception e) {
				throw new ServletException("Error processing authentication request", e);
			}
    	}
	}

	private void authorizationFlow(OpenIdRequest r, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		if ( ! "code".equals(r.getResponseType()))
       		throw new ServletException("Expected response_type=code, but found: "+r.getResponseType());
		
		HttpSession session = req.getSession();
		session.setAttribute(SessionConstants.OPENID_REQUEST, r);
		session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
		
        RequestDispatcher dispatcher = req.getRequestDispatcher(LoginServlet.URI);
        dispatcher.forward(req, resp);
	}

	private void implicitFlow(OpenIdRequest r, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		if ( ! "id_token".equals(r.getResponseType()) && 
				! "id_token token".equals(r.getResponseType() ))
       		throw new ServletException("Expected response_type=id_token or response_type=id_token token, but found: "+r.getResponseType());
		
    	if (r.getNonce() == null)
    		throw new ServletException("Nonce is required, but not received");

    	HttpSession session = req.getSession();
		session.setAttribute(SessionConstants.OPENID_REQUEST, r);
		session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
		String user = (String) session.getAttribute(SessionConstants.SEU_USER);

		if (user != null)
		{
			AuthorizationResponse.generateResponse(getServletContext(), req, resp);
		} else {
            RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
            dispatcher.forward(req, resp);
		}
	}

	private void checkParameters(OpenIdRequest r) throws ServletException {
    	boolean found  = false;
    	if (r.getScope() != null) {
	    	for (String s: r.getScope().split(" +"))
	    	{
	    		if (s.equalsIgnoreCase("openid")) found = true;
	    	}
    	}
    	if (! found)
    		throw new ServletException("The requested scope does not contain the scope openid: "+r.getScope());
		
    	if (r.getFederationMember() == null)
    		throw new ServletException("Unknown client id "+r.getClientId());
    	
//    	if (r.getState() == null)
//    		throw new ServletException("State parameter is required but not found");
    	
    	if (r.getResponseType() == null)
    		throw new ServletException("response_type parameter is required but not found");
    	
    	if ( ! "code".equals( r.getResponseType()) && 
    			! "id_token".equals(r.getResponseType()) &&
    			! "id_token token".equals(r.getResponseType()) &&
    			! "code id_token".equals(r.getResponseType()) &&
    			! "code token".equals(r.getResponseType()) &&
    			! "code id_token token".equals(r.getResponseType())
    			)
       		throw new ServletException("Wrong value for response_type: "+r.getResponseType());
	}
}
