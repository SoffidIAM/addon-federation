package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.Principal;
import java.text.Format;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.server.session.JDBCSessionManager.Session;
import org.opensaml.saml2.core.AuthnContext;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.Password;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class PasswordChangeRequiredAction extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/passwordChangeRequiredAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        HttpSession session = req.getSession();
        String user = (String) session.getAttribute(SessionConstants.SEU_TEMP_USER);
        Password pOld = (Password) session.getAttribute(SessionConstants.SEU_TEMP_PASSWORD);
        if (user == null) {
            throw new ServletException(Messages.getString("PasswordChangeRequiredAction.expired.session")); //$NON-NLS-1$
        }
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
       
            PasswordManager pm = new PasswordManager();
            try {
                pm.changePassword(user, pOld, new Password(p1));
                error = null;
            } catch (UnknownUserException e) {
                error = String.format(Messages.getString("PasswordChangeRequiredAction.unknown.user"), user); //$NON-NLS-1$
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
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
            dispatcher.forward(req, resp);
        } else {
        	try {
        		new Autenticator().autenticate(user, req, resp, AuthnContext.PPT_AUTHN_CTX, false);
        	} catch (Exception e)
        	{
                error = Messages.getString("PasswordChangeRequiredAction.internal.error")+e.toString(); //$NON-NLS-1$
                req.setAttribute("ERROR", error); //$NON-NLS-1$
                RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
                dispatcher.forward(req, resp);
        	}
        }
    }

}
