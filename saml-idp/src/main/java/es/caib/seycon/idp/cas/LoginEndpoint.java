package es.caib.seycon.idp.cas;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.api.TokenType;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LoginEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		OpenIdRequest r;
		try {
			IdpConfig config = IdpConfig.getConfig();
		
	    	req.getSession().setAttribute("soffid-session-type", "cas");
	    	r = new OpenIdRequest();
	    	
	    	r.setType(TokenType.TOKEN_CAS);
	    	final String serviceName = req.getParameter("service");
	    	if (serviceName == null)
	    		throw new ServletException ("Missing service parameter");
			r.setFederationMember( findFederationMember(config, serviceName));
	    	if (r.getFederationMember() == null)
	    		throw new Exception("Unkwnown service "+serviceName);
	    	if (r.getFederationMember() != null && r.getRedirectUrl() == null) {
	    		if (r.getFederationMember().getOpenidUrl() != null && !r.getFederationMember().getOpenidUrl().isEmpty())
	    		r.setRedirectUrl(r.getFederationMember().getOpenidUrl().iterator().next());
	    	}
	    	String method = req.getParameter("method");
	    	if ( ! ("GET".equals(method) || "POST".equals(method) || "HADER".equals(method))) {
	    		method = "GET";
	    	}
	    	r.setResponseType(method);
	    	HttpSession session = req.getSession(true);
	    	if (r.getFederationMember() != null) {
		    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
	        	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, null);
	    	}	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
    	try {
	    	HttpSession session = req.getSession();
	    	session.setAttribute(SessionConstants.OPENID_REQUEST, r);
	    	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, r.getFederationMember().getPublicId());
	    	
	    	String user = (String) req.getSession().getAttribute(SessionConstants.SEU_USER);
	    	if (req.getParameter("renew") != null && user != null) {
	    		LoginResponse.generateResponse(getServletContext(), req, resp, "P", null);
	    		return;
	    	} 
	    	RequestDispatcher dispatcher = req.getRequestDispatcher(LoginServlet.URI);
	    	dispatcher.forward(req, resp);
	    	
    	} catch (Exception e) {
            generateError(r, "server_error", e.toString(), resp);
		}
	}


	private FederationMember findFederationMember(IdpConfig config, final String serviceName)
			throws InternalErrorException {
		int length = -1;
		FederationMember last= null;
		for ( FederationMember fm: config.getFederationService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "S")) {
			if (fm.getServiceProviderType() == ServiceProviderType.CAS) {
				if (fm.getOpenidUrl() != null) {
					for (String url: fm.getOpenidUrl()) {
						if (serviceName.startsWith(url) && (length < 0 ||  url.length() < length)) {
							last = fm;
							length = url.length();
						}
					}
				}
			}
		}
		return last;
	}


	private void generateError(OpenIdRequest r, String error, String description, HttpServletResponse resp) throws IOException, ServletException {
		throw new ServletException(description);
	}

}