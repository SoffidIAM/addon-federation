package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.idp.server.AuthenticationContext;
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
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        String error = null;
        
        try {
        	if ( ctx != null && ctx.getChallenge() != null &&
        			ctx.getChallenge().isResendAvailable()) {
        		boolean voice = "true".equals(req.getParameter("voice"));
        		new RemoteServiceLocator().getOTPValidationService().resendToken(ctx.getChallenge(), voice);
        		req.setAttribute("ERROR", voice ? "A voice system is going to call you. Please, wait": 
        			"The PIN has ben resent by SMS"); //$NON-NLS-1$
        	}
		} catch (Exception e1) {
       		req.setAttribute("ERROR", "Cannot send SMS");
		}

        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }
}

