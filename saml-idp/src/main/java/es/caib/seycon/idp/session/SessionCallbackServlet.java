package es.caib.seycon.idp.session;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.util.storage.StorageService;
import org.opensaml.xml.util.DatatypeHelper;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.InternalErrorException;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.textformatter.TextFormatter;

public class SessionCallbackServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/Soffid.sso"; //$NON-NLS-1$


    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String id = req.getParameter("id");
    	if (id != null && SessionListener.isSessionAlive(id))
    		resp.getOutputStream().println("OK");
    	else
    		resp.getOutputStream().println("NO");
    }
    

}
