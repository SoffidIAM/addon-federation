package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.LoginTimeoutHandler;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.shibext.SessionPrincipal;
import es.caib.seycon.ng.exception.InternalErrorException;

public class CancelAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/cancelAction"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	doPost(req, resp);
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
    	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
    	if (authCtx == null)
       		getServletContext().getRequestDispatcher(LogoutServlet.URI).forward(req, resp);
    	
    	if (authCtx.getUser() != null) {
    		authCtx.setUser(null);
    		try {
				authCtx.initialize(req);
			} catch (																															Exception e) {
				new AuthenticationContext().store(req);
			}
    	}

    	HttpSession session = req.getSession();
    	String sessionType = (String) session.getAttribute("soffid-session-type");
    	String reason = new LoginTimeoutHandler().isTimedOut(req) ? "Timeout": "Access denied by user";
    			;
        if ("saml".equals(sessionType))
        {
	        String returnPath = (String) session.getAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
	        
	        req.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, reason);
			Saml2LoginContext saml2LoginContext = (Saml2LoginContext)HttpServletHelper.getLoginContext(req);
			if (saml2LoginContext != null) {
				saml2LoginContext.setAuthenticationAttempted();
				saml2LoginContext.setPrincipalAuthenticated(false);
				saml2LoginContext.setAuthenticationFailure(new AuthenticationException(reason));
			}
			
            AuthenticationEngine.returnToAuthenticationEngine(req, resp);
        }  else if ("openid".equals(sessionType)) {
	    	OpenIdRequest r = (OpenIdRequest) session.getAttribute(SessionConstants.OPENID_REQUEST);
	    	
	    	resp.sendRedirect(r.getRedirectUrl() + (r.getRedirectUrl().contains("?") ? "&": "?") +
	    			"error=access_denied&error_description="+
	    				URLEncoder.encode(reason , "UTF-8")+
	    				(r.getState() != null ? "&state="+r.getState(): ""));
        } else {
       		getServletContext().getRequestDispatcher(LogoutServlet.URI).forward(req, resp);
	
    	}
    
    	LogoutServlet.expireSession(req);
    }
}
