package es.caib.seycon.idp.ui.rememberPassword;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.server.session.JDBCSessionManager.Session;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.metadata.EntityDescriptor;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.rememberPassword.common.RememberPasswordChallenge;
import com.soffid.iam.addons.rememberPassword.common.UserAnswer;
import com.soffid.iam.addons.rememberPassword.service.RememberPasswordUserService;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.Password;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.ErrorServlet;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.PasswordChangeRequiredForm;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.PolicyCheckResult;
import es.caib.seycon.ng.comu.TipusDada;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.servei.DadesAddicionalsService;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordResetAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/passwordResetAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        HttpSession session = req.getSession();
        RememberPasswordChallenge challenge = (RememberPasswordChallenge) session.getAttribute("rememberPasswordChallenge");

        if (challenge == null) 
        {
            throw new ServletException(Messages.getString("PasswordChangeRequiredAction.expired.session")); //$NON-NLS-1$
        }
        String user = (String) session.getAttribute("account");
        resp.addHeader("Cache-Control", "no-cache"); //$NON-NLS-1$ //$NON-NLS-2$

        String p1 = req.getParameter("j_password1"); //$NON-NLS-1$
        String p2 = req.getParameter("j_password2"); //$NON-NLS-1$
        String error = null;
        if (p1 == null || p1.length() == 0) {
            error = Messages.getString("PasswordChangeRequiredAction.missing.pasword"); //$NON-NLS-1$
        } else if (p2 == null || p2.length() == 0) {
            error = Messages.getString("PasswordChangeRequiredAction.missing.second.password"); //$NON-NLS-1$
        } else if (! p1.equals(p2)) {
            error = Messages.getString("PasswordChangeRequiredAction.password.mismatch"); //$NON-NLS-1$
        } else {
            challenge.setPassword(new Password(p1));
            
            try
            {
	           	RemoteServiceLocator rsl = new RemoteServiceLocator();
	            RememberPasswordUserService rpus = (RememberPasswordUserService) rsl.getRemoteService(RememberPasswordUserService.REMOTE_PATH);
	            rpus.resetPassword(challenge);
            } catch (InvalidPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeRequiredAction.wrong.password"), user); //$NON-NLS-1$
            } catch (BadPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeRequiredAction.password.not.suitable")); //$NON-NLS-1$
            } catch (Exception e) {
                error = Messages.getString("PasswordChangeRequiredAction.internal.error")+e.toString(); //$NON-NLS-1$
                e.printStackTrace();
            }
        }
        if (error != null) {
            req.setAttribute("ERROR", error); //$NON-NLS-1$
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordResetForm.URI);
            dispatcher.forward(req, resp);
        } else {
        	try {
        		new Autenticator().autenticate(user, req, resp, AuthnContext.PPT_AUTHN_CTX, false);
        	} 
        	catch (Exception e)
        	{
                error = Messages.getString("PasswordChangeRequiredAction.internal.error")+e.toString(); //$NON-NLS-1$
                req.setAttribute("ERROR", error); //$NON-NLS-1$
                RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordResetForm.URI);
                dispatcher.forward(req, resp);
        	}
        }
    }

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost(req, resp);
	}

    
}
