package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LoginServlet extends LangSupportServlet {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/login"; //$NON-NLS-1$

    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
        HttpSession session = req.getSession();
        
        String method = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
        if (session.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM) == null)
        	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, method);
        else
        	method = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
        
        String entityId = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        if (session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM) == null)
        	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, entityId);
        else
        	entityId = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM); 

        Autenticator auth = new Autenticator();
        boolean previousAuth = false;
		try {
			previousAuth = auth.validateCookie(getServletContext(), req, resp);
		} catch (Exception e1) {
			LogFactory.getLog(getClass()).warn("Error decoding authentication cookie", e1);
		}
		
        if (!previousAuth)
        {
        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
        	if (authCtx == null)
        	{
        		try {
        			authCtx = new AuthenticationContext();
        			authCtx.setPublicId(entityId);
        			if (method != null)
        			{
        				authCtx.setSamlRequestedAuthenticationMethod(Collections.singleton(method));
        			}
        			authCtx.initialize();
        			authCtx.store(req);
        		} catch (Exception e1) {
        			LogFactory.getLog(getClass()).warn("Error decoding authentication cookie", e1);
        			throw new ServletException("Error decoding authentication cookie", e1);
        		}
        	}
        	else
        	{
        		try {
        			authCtx.setPublicId(entityId);
    				authCtx.setSamlRequestedAuthenticationMethod(Collections.singleton(method));
					if (authCtx.isPreviousAuthenticationMethodAllowed(req))
					{
						auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, authCtx.getUsedMethod(), false);
						return;
					}
				} catch (Exception e) {
					throw new ServletException("Error authenticating user", e);
				}
        	}
   			resp.sendRedirect(UserPasswordFormServlet.URI);
        }
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
