package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.Principal;
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
import es.caib.seycon.Password;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.shibext.LogRecorder;

public class UserPasswordAction extends HttpServlet {
    LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/passwordLoginAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$
        

        String method = req.getParameter("j_method");
        String u = req.getParameter("j_username"); //$NON-NLS-1$
        String p = req.getParameter("j_password"); //$NON-NLS-1$
        String error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
       
        if (u == null || u.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.user.name"); //$NON-NLS-1$
        } else if ( p == null || p.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.password"); //$NON-NLS-1$
        } else {
            PasswordManager v = new PasswordManager();

            try {
                if (v.validate(u, new Password(p))) {
                    if (v.mustChangePassword()) {
                        logRecorder.addErrorLogEntry(u, Messages.getString("UserPasswordAction.7"), req.getRemoteAddr()); //$NON-NLS-1$
                        HttpSession s = req.getSession();
                        s.setAttribute(SessionConstants.SEU_TEMP_USER, u);
                        s.setAttribute(SessionConstants.SEU_TEMP_PASSWORD, new Password(p));
                        RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
                        dispatcher.forward(req, resp);
                    } else {
                        new Autenticator().autenticate(u, req, resp, AuthnContext.PPT_AUTHN_CTX, false);
                    }
                    return ;
                } else {
                    logRecorder.addErrorLogEntry(u, Messages.getString("UserPasswordAction.8"), req.getRemoteAddr()); //$NON-NLS-1$
                }
            } catch (UnknownUserException e) {
            } catch (Exception e) {
                error = Messages.getString("UserPasswordAction.internal.error")+e.toString(); //$NON-NLS-1$
                e.printStackTrace();
            }
        }
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }

}
