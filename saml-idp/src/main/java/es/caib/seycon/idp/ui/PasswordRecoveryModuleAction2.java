package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserService;
import com.soffid.iam.api.Password;

import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.addons.passrecover.remote.RemoteServiceLocator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class PasswordRecoveryModuleAction2 extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/passwordRecoveryPluginAction2"; //$NON-NLS-1$
    org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        HttpSession session = req.getSession();
        
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        if (ctx == null || ctx.getCurrentUser() == null ||
        		ctx.getRecoverChallenge() == null ||
        		!ctx.getRecoverChallenge().isAnswered())
        {
        	resp.sendRedirect(UserPasswordFormServlet.URI);
        	return;
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
        	try {
        		RecoverPasswordUserService svc = (RecoverPasswordUserService) 
        			new RemoteServiceLocator()
        			.getRemoteService(RecoverPasswordUserService.REMOTE_PATH);
        	
            	RecoverPasswordChallenge ch = ctx.getRecoverChallenge();
            	ch.setPassword(new Password(p1));
            	svc.resetPassword(ch);
            	ctx.setRecoverChallenge(null);
            } catch (BadPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeRequiredAction.password.not.suitable")); //$NON-NLS-1$
            } catch (Exception e) {
                error = Messages.getString("PasswordChangeRequiredAction.internal.error") ;//$NON-NLS-1$
                LogFactory.getLog(getClass()).info("Error changing password ", e);
                e.printStackTrace();
            }
        }

        if (error != null) {
    		if (ctx != null)
    		{
    			try {
					ctx.authenticationFailure(ctx.getUser(), error);
				} catch (InternalErrorException e) {
				}
    		}
            req.setAttribute("ERROR", error); //$NON-NLS-1$
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
            dispatcher.forward(req, resp);
        } else {
        	try {
    	        RequestDispatcher dispatcher = req.getRequestDispatcher(ActivatedFormServlet.URI);
    	        dispatcher.forward(req, resp);
        	} catch (Exception e)
        	{
        		log.warn("Error reseting password", e);
                error = Messages.getString("PasswordChangeRequiredAction.internal.error")+e.toString(); //$NON-NLS-1$
                req.setAttribute("ERROR", error); //$NON-NLS-1$
                RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
                dispatcher.forward(req, resp);
        	}
        }
    }

}
