package es.caib.seycon.idp.ui;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.api.Password;

import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class UserPasswordAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

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
                        return;
                    } else {
	            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	            		ctx.authenticated(u, "P", resp);
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false);
	            			return;
	            		}
	            		else
	            		{
	            	        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
	            	        dispatcher.forward(req, resp);
	            	        return;
	            		}
                    }
                } else {
            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
    	    		if (ctx != null)
    	    		{
    	    			try {
    						ctx.authenticationFailure();
    					} catch (InternalErrorException e) {
    					}
    	    		}
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
