package es.caib.seycon.idp.ui;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LoginServlet extends LangSupportServlet {
    
    public static final String URI = "/login"; //$NON-NLS-1$

    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
        String method = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
        String entityId = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        HttpSession session = req.getSession();
        session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, method);
        session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, entityId);
        Autenticator auth = new Autenticator();
        boolean previousAuth = false;
		try {
			previousAuth = auth.validateCookie(req, resp);
		} catch (Exception e1) {
			LogFactory.getLog(getClass()).warn("Error decoding authentication cookie", e1);
		}
        if (!previousAuth)
        {
	        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);

	        if (amf.requiresKerberos())
	   			resp.sendRedirect(NtlmAction.URI);
	        else if (amf.allowKerberos() && auth.hasKerberosCookie(req))
	   			resp.sendRedirect(NtlmAction.URI);
	        else if (amf.allowUserPassword()) {
	   			resp.sendRedirect(UserPasswordFormServlet.URI);
	        } else if (amf.allowTls()) {
	            IdpConfig idpConfig;
	            try {
					idpConfig = IdpConfig.getConfig();
		            resp.sendRedirect("https://"+idpConfig.getHostName()+":"+idpConfig.getClientCertPort()+CertificateAction.URI);
				} catch (Exception e) {
		    		req.setAttribute("ERROR", e.toString()); //$NON-NLS-1$
		            RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
		            dispatcher.forward(req, resp);
				}
	        } else {
	            resp.sendRedirect(SignatureForm.URI);
	        }
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
