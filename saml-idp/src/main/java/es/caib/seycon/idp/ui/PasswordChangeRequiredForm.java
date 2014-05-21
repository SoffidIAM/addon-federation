package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.InternalErrorException;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.textformatter.TextFormatter;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordChangeRequiredForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/passwordChangeRequired"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HttpSession session = req.getSession();
            
            String user = (String) session.getAttribute(SessionConstants.SEU_TEMP_USER);
            if (user == null) {
                throw new ServletException(Messages.getString("PasswordChangeRequiredForm.expired.session")); //$NON-NLS-1$
            }
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("passwordChangeLoginUrl", PasswordChangeRequiredAction.URI); //$NON-NLS-1$
            
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	
        	
        	g.addArgument("policy", logonService.getPasswordPolicy(user, IdpConfig.getConfig().getDispatcher().getCodi()));

            
            g.generate(resp, "passwordChangeRequired.html"); //$NON-NLS-1$
        } catch (TextFormatException e) {
            throw new ServletException(e);
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
