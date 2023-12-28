package es.caib.seycon.idp.ui;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.LoginTimeoutHandler;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class LoginServlet extends LangSupportServlet {
    
    private static final String SOFFID_LOGIN_TIME_ATTR = "$$soffid$loginTime";
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
       		new LoginTimeoutHandler().registerSession(req);
       		
       		boolean timeout = checkSessionDuration(req, resp);
       		
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
    				
				if (!timeout && !authCtx.isAlwaysAskForCredentials() && authCtx.isPreviousAuthenticationMethodAllowed(req) &&
						auth.getSession(req, false) != null)
				{
					auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, authCtx.getUsedMethod(), false, authCtx.getHostId(resp));
					return;
				}
        	}
        	if (! timeout && 
        			!authCtx.isAlwaysAskForCredentials() && auth.validateCookie(getServletContext(), req, resp, authCtx.getHostId(resp)))
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

    private boolean checkSessionDuration(HttpServletRequest req, HttpServletResponse resp) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
    	Long l = IdpConfig.getConfig().getFederationMember().getMaxSessionDuration();
    	if (l != null) {
    		HttpSession s = req.getSession();
    		Long start = (Long) s.getAttribute(SOFFID_LOGIN_TIME_ATTR);
    		if (start == null) {
    			start = System.currentTimeMillis();
    			s.setAttribute(SOFFID_LOGIN_TIME_ATTR, start);
    		}
    		long end = start.longValue() + l.longValue() * 1000;
    		if (end < System.currentTimeMillis()) {
    			// Session has been finished
    			start = System.currentTimeMillis();
    			s.setAttribute(SOFFID_LOGIN_TIME_ATTR, start);
           		AuthenticationContext.remove(req);
           		new Autenticator().clearCookies(req, resp);
           		return true;
    		}
    	}
    	return false;
	}

	private boolean certificateLogin(AuthenticationContext authCtx, HttpServletRequest req, HttpServletResponse resp) throws InternalErrorException, IOException, UnknownUserException {
    	if (authCtx.getNextFactor().contains("C")) {
    		CertificateValidator v = new CertificateValidator();
    		try {
	    		String certUser = v.validate(req);
	    		if (certUser != null) {
    				authCtx.authenticated(certUser, "C", resp);
    				authCtx.store(req);
    				Date warning = IdpConfig.getConfig().getFederationService()
    						.getCertificateExpirationWarning(Arrays.asList( v.getCerts(req) ));
    				if (warning != null) 
    					authCtx.setCertificateWarning(warning);
    				if ( authCtx.isFinished())
    				{
    					if (authCtx.getCertificateWarning() != null)
    	        			resp.sendRedirect(CertificateAction.URI);
    					else
    						new Autenticator().autenticate2(certUser, getServletContext(),req, resp, authCtx.getUsedMethod(), true, authCtx.getHostId(resp));
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
