package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.idp.shibext.LogRecorder;

public class ResendSmsAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/resendSmsAction"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        String error = null;
        
        try {
        	if ( ctx != null && ctx.getChallenge() != null &&
        			ctx.getChallenge().isResendAvailable()) {
        		boolean voice = "true".equals(req.getParameter("voice")); //$NON-NLS-1$ //$NON-NLS-2$
        		new RemoteServiceLocator().getOTPValidationService().resendToken(ctx.getChallenge(), voice);
        		req.setAttribute("ERROR", voice ? Messages.getString("ResendSmsAction.3"):  //$NON-NLS-1$ //$NON-NLS-2$
        			Messages.getString("ResendSmsAction.0")); //$NON-NLS-1$
        	}
		} catch (Exception e1) {
       		req.setAttribute("ERROR", Messages.getString("ResendSmsAction.5")); //$NON-NLS-1$ //$NON-NLS-2$
		}

        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }
}

