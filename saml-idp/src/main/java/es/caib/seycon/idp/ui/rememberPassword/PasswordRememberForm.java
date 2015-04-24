package es.caib.seycon.idp.ui.rememberPassword;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
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

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.addons.rememberPassword.common.MissconfiguredRecoverException;
import com.soffid.iam.addons.rememberPassword.common.RememberPasswordChallenge;
import com.soffid.iam.addons.rememberPassword.common.UserAnswer;
import com.soffid.iam.addons.rememberPassword.service.Messages;
import com.soffid.iam.addons.rememberPassword.service.RememberPasswordUserService;

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
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.textformatter.TextFormatter;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.ErrorServlet;
import es.caib.seycon.idp.ui.HtmlGenerator;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordRememberForm extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/passwordRememberForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$

    	HttpSession session = req.getSession();
        
        String email = (String) session.getAttribute("rememberPasswordEmail");

        try {
            RememberPasswordChallenge challenge = (RememberPasswordChallenge) session.getAttribute("rememberPasswordChallenge");
            Integer question = (Integer) session.getAttribute("rememberPasswordQuestion");
            
	    	IdpConfig config = IdpConfig.getConfig();

            if (challenge == null)
            {
            	String server = (String) session.getAttribute("recoverServer");
            	if (server == null)
            	{
            		server = ServerLocator.getInstance().getServer();
            		session.setAttribute("recoverServer", server);
            	}
            	RemoteServiceLocator rsl = new RemoteServiceLocator(server);
            	RememberPasswordUserService rpus = (RememberPasswordUserService) rsl.getRemoteService(RememberPasswordUserService.REMOTE_PATH);
            	UsuariService us = (UsuariService) rsl.getUsuariService();
            	Usuari user = us.findUsuariByCodiTipusDadaIValorTipusDada("EMAIL", email);

            	if (user == null)
            	{
            		user = us.findUsuariByCodiUsuari(email);
            	}

            	if (user != null)
        			challenge = rpus.requestChallenge(user.getCodi());
            	else
            		challenge = rpus.requestChallenge(email, config.getDispatcher().getCodi());
                session.setAttribute("rememberPasswordChallenge", challenge);
                question = null;
            }
            
            if (question == null)
            	question = Integer.valueOf(0);
            
            int i = 0;
            Iterator<UserAnswer> it = challenge.getQuestions().iterator();
            UserAnswer ua = null;
            while ( i <= question.intValue())
            {
            	ua = it.next();
            	i ++;
            }
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("targetUrl", PasswordRememberAction.URI); //$NON-NLS-1$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("question", ua.getQuestion());
            g.addArgument("questionId", question.toString());
            g.addArgument("user", challenge.getUser());
            g.generate(resp, "rememberPassword/rememberPassword.html"); //$NON-NLS-1$
        } catch (es.caib.seycon.ng.exception.UnknownUserException e) {
        	req.setAttribute("ERROR", 
        			String.format(es.caib.seycon.idp.ui.Messages.getString("RecoverPassword.invalidUser"),
        					email));
        	req.getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
        } catch (MissconfiguredRecoverException e) {
        	req.setAttribute("ERROR", 
        			String.format(es.caib.seycon.idp.ui.Messages.getString("RecoverPassword.invalidUser"),
        					email));
        	req.getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
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
