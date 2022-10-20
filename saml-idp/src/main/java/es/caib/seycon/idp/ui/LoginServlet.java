package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collections;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class LoginServlet extends LangSupportServlet {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/login"; //$NON-NLS-1$
	Log log = LogFactory.getLog(getClass());
	
    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
        HttpSession session = req.getSession();
        
        String entityId = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        if (entityId != null)
        	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, entityId);
        else
        	entityId = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM); 

       	try {
       		Autenticator auth = new Autenticator();
        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
        	if (authCtx == null )
        	{
    			authCtx = new AuthenticationContext();
    			authCtx.setPublicId(entityId);
    			authCtx.initialize(req);
    			authCtx.store(req);
        	}
        	else
        	{
    			authCtx.setPublicId(entityId);
    			authCtx.updateAllowedAuthenticationMethods();
   				authCtx.setSamlRequestedAuthenticationMethod(null);
    				
				if (!authCtx.isAlwaysAskForCredentials() && authCtx.isPreviousAuthenticationMethodAllowed(req) &&
						auth.getSession(req, false) != null)
				{
					auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, authCtx.getUsedMethod(), false);
					return;
				}
        	}
        	if (!authCtx.isAlwaysAskForCredentials() && auth.validateCookie(getServletContext(), req, resp))
        		return;
        	else {
        		authCtx.initialize(req);
        		if (! certificateLogin(authCtx, req, resp))
        			resp.sendRedirect(UserPasswordFormServlet.URI);
        	}
    	} catch (Exception e) {
    		log.warn ("Error authenticating user", e);
    		throw new ServletException("Error authenticating user", e);
    	}
    }

    private boolean certificateLogin(AuthenticationContext authCtx, HttpServletRequest req, HttpServletResponse resp) throws InternalErrorException, IOException, UnknownUserException {
    	if (authCtx.getNextFactor().contains("C")) {
    		CertificateValidator v = new CertificateValidator();
    		try {
	    		String certUser = v.validate(req);
	    		if (certUser != null) {
    				authCtx.authenticated(certUser, "C", resp);
    				authCtx.store(req);
    				if ( authCtx.isFinished())
    				{
    					new Autenticator().autenticate2(certUser, getServletContext(),req, resp, authCtx.getUsedMethod(), true);
    					return true;
    				}
    			}
    		} catch (Exception e) {
    			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
    			LogFactory.getLog(getClass()).info("Error validating certificate ", e);
    		}
    	}
        return false;
	}

	@Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	super.doGet(req, resp);
        process (req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	super.doPost(req, resp);
        process (req, resp);
    }
}
