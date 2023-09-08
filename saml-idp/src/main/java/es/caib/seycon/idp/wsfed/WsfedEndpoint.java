package es.caib.seycon.idp.wsfed;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.AllowedScope;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class WsfedEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	static HashMap<String, Long> lastSectorUpdate = new HashMap<>();
	
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		IdpConfig config;
		WsfedRequest r;
		try {
			config = IdpConfig.getConfig();
		
	    	req.getSession().setAttribute("soffid-session-type", "ws-fed");
	    	r = new WsfedRequest();
	    	
	    	String publicId = req.getPathInfo();
	    	if (publicId.startsWith("/")) publicId = publicId.substring(1);
			r.setPublicId(publicId);
			r.setType(req.getParameter("wa"));
			String replyUrl = req.getParameter("wreply");
			r.setReplyUrl(replyUrl);
			r.setState(req.getParameter("state"));
	    	r.setFederationMember( config.getFederationService().findFederationMemberByPublicId(r.getPublicId()) );
	    	if (r.getFederationMember() != null && r.getReplyUrl() == null) {
	    		if (r.getFederationMember().getOpenidUrl() != null && !r.getFederationMember().getOpenidUrl().isEmpty())
	    			r.setReplyUrl(r.getFederationMember().getOpenidUrl().iterator().next());
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
	    	HttpSession session = req.getSession();
	    	session.setAttribute(SessionConstants.WSFED_REQUEST, r);
	    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
	    	
			String user = (String) req.getSession().getAttribute(SessionConstants.SEU_USER);
			if (user != null) {
				WsfedResponse.generateResponse(getServletContext(), req, resp, "P", null);
				return;
			} 
			RequestDispatcher dispatcher = req.getRequestDispatcher(LoginServlet.URI);
			dispatcher.forward(req, resp);
	    	
    	} catch (Exception e) {
            generateError(r, "server_error", e.toString(), resp);
		}
	}

	private void generateError(WsfedRequest r, String error, String description, HttpServletResponse resp) throws IOException, ServletException {
		throw new ServletException(description);
	}

	private boolean checkParameters(WsfedRequest r, HttpServletResponse resp) throws ServletException, IOException {
    	boolean found  = false;
    	if (r.getFederationMember() == null)
    	{
            generateError(r, "unauthorized_client", "Unknown public id "+r.getPublicId(), resp);
            return false;
    	}
    	
    	if (r.getType() == null)
    	{
            generateError(r, "unsupported_response_type", "Wrong value for wa: "+r.getType(), resp);
            return false;
    	}
    	
    	if ( ! "wsignin1.0".equals( r.getType()) && 
    			! "wsignout1.0".equals(r.getType()) 
    			)
    	{
            generateError(r, "unsupported_response_type", "Wrong value for response_type: "+r.getType(), resp);
            return false;
    	}


    	if (r.getReplyUrl() == null)
    	{
            generateError(r, "invalid_request", "Missing redirect_uri", resp);
            return false;
    	}
    	boolean ok = isReturnUrlValid(r);
    	if (!ok) {
    		generateError(r, "invalid_request", "The requested return URL is not accepted "+r.getReplyUrl(), resp);
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

	private boolean isReturnUrlValid(WsfedRequest r) {
		boolean ok = false;
    	for (String url: r.getFederationMember().getOpenidUrl()) {
    		if (r.getReplyUrl().equals(url) || r.getReplyUrl().startsWith(url+"?")) 
    			ok = true;
    		if (url.endsWith("*") && r.getReplyUrl().startsWith(url.substring(0, url.length()-1))) 
    			ok = true;
    	}
		return ok;
	}
}
