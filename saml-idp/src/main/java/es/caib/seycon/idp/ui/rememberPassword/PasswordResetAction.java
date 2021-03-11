package es.caib.seycon.idp.ui.rememberPassword;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.rememberPassword.common.RememberPasswordChallenge;
import com.soffid.iam.addons.rememberPassword.service.RememberPasswordUserService;
import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;

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
            challenge.setPassword(new es.caib.seycon.ng.comu.Password(p1));
            
            try
            {
            	String server = (String) session.getAttribute("recoverServer");
            	if (server == null)
            	{
            		server = ServerLocator.getInstance().getServer();
            		session.setAttribute("recoverServer", server);
            	}
            	RemoteServiceLocator rsl = new RemoteServiceLocator(server);
	            RememberPasswordUserService rpus = (RememberPasswordUserService) rsl.getRemoteService(RememberPasswordUserService.REMOTE_PATH);
	            rpus.resetPassword(challenge);
            } catch (InvalidPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeRequiredAction.wrong.password"), user); //$NON-NLS-1$
            } catch (BadPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeRequiredAction.password.not.suitable")); //$NON-NLS-1$
            } catch (Exception e) {
                LogFactory.getLog(getClass()).info("Error reseting password ", e);
                error = Messages.getString("PasswordChangeRequiredAction.internal.error"); //$NON-NLS-1$
            }
        }
        if (error != null) {
    		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
    		if (ctx != null)
    		{
    			try {
					ctx.authenticationFailure(ctx.getUser());
				} catch (InternalErrorException e) {
				}
    		}
            req.setAttribute("ERROR", error); //$NON-NLS-1$
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordResetForm.URI);
            dispatcher.forward(req, resp);
        } else {
        	try {
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        		ctx.authenticated(user, "P", resp);
        		ctx.store(req);
        		if ( ctx.isFinished())
        		{
        			new Autenticator().autenticate2(user, getServletContext(), req, resp, ctx.getUsedMethod(), false);
        		} else {
        		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        		    dispatcher.forward(req, resp);
        		}
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
