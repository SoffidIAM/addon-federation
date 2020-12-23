package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;

public class ConsentAction extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

	public static final String URI = "/registerConsent"; //$NON-NLS-1$

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String accept = req.getParameter("accept"); //$NON-NLS-1$
		String error = null;
		try {
			if ("true".equals(accept)) {
	        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
	        	if (authCtx.isFinished())
	        	{
	        		authCtx.addConsent();
	                Autenticator auth = new Autenticator();
	                auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, authCtx.getUsedMethod(), false );
	        	} else {
					resp.sendRedirect(CancelAction.URI);
	        	}
			} else {
				resp.sendRedirect(CancelAction.URI);
				
			}
		} catch (Exception e) {
			error = "An internal error has been detected: " + e.toString();
			e.printStackTrace();
		}

		if (error != null) {
	        req.setAttribute("ERROR", error); //$NON-NLS-1$
	        RequestDispatcher dispatcher = req.getRequestDispatcher(ErrorServlet.URI);
	        dispatcher.forward(req, resp);
		}
	}

}
