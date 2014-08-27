package es.caib.seycon.idp.ui.rememberPassword;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Principal;
import java.util.Collection;
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

import com.soffid.iam.addons.rememberPassword.common.RememberPasswordChallenge;

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
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.HtmlGenerator;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.UserAccount;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordResetForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/rememberPasswordForm2"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HttpSession session = req.getSession();
            
            RememberPasswordChallenge challenge = (RememberPasswordChallenge) session.getAttribute("rememberPasswordChallenge");

            if (challenge == null) {
                throw new ServletException(Messages.getString("PasswordChangeRequiredForm.expired.session")); //$NON-NLS-1$
            }
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("passwordChangeLoginUrl", PasswordResetAction.URI); //$NON-NLS-1$
            
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	
        	String dispatcher = IdpConfig.getConfig().getDispatcher().getCodi();
        	Usuari usuari = serverService.getUserInfo(challenge.getUser(), null);
        	Collection<UserAccount> accounts = serverService.getUserAccounts(usuari.getId(), dispatcher);
        	if (accounts.isEmpty())
        	{
        		g.addArgument("policy", "");
        		g.addArgument("user", usuari.getCodi());
        		session.setAttribute("account", usuari.getCodi());
        	}
        	else
        	{
        		UserAccount acc = accounts.iterator().next();	
        		session.setAttribute("account", acc.getName());
        		g.addArgument("policy", logonService.getPasswordPolicy(acc.getName(), acc.getDispatcher()));
        		g.addArgument("user", acc.getName());
        	}

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
