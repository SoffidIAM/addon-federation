package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.OTPValidationService;

import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.UnknownUserException;

public class OTPAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/otpLoginAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);

        String u = req.getParameter("j_username"); //$NON-NLS-1$
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        if (u == null && ctx != null)
        	u = ctx.getUser();
        String p = req.getParameter("j_password"); //$NON-NLS-1$
        String error = "";
        
       
        if (u == null || u.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.user.name"); //$NON-NLS-1$
        } else if ( p == null || p.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.password"); //$NON-NLS-1$
        } else {
            try {
            	OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
            	IdpConfig config = IdpConfig.getConfig();
            	
            	User user = new RemoteServiceLocator().getServerService().getUserInfo(u, config.getSystem().getName());
            	
            	if (ctx == null) {
            		error = Messages.getString("OTPAction.notoken"); //$NON-NLS-1$
                    logRecorder.addErrorLogEntry(u, error, req.getRemoteAddr()); //$NON-NLS-1$
            	} else {
	            	Challenge ch = ctx.getChallenge();
	            	if (ch == null ||  ch.getCardNumber() == null)
	            	{
	            		error = Messages.getString("OTPAction.notoken"); //$NON-NLS-1$
	                    logRecorder.addErrorLogEntry(u, error, req.getRemoteAddr()); //$NON-NLS-1$
	            	}
	            	else if (v.validatePin(ch, p)) {
	            		Set<String> nf = ctx.getNextFactor();
	            		if (nf.contains("I"))
	            			ctx.authenticated(u, "I", resp); //$NON-NLS-1$
	            		else if (nf.contains("S")) 
	            			ctx.authenticated(u, "S", resp); //$NON-NLS-1$
	            		else if (nf.contains("M")) 
	            			ctx.authenticated(u, "M", resp); //$NON-NLS-1$
	            		else if (nf.contains("O")) 
	            			ctx.authenticated(u, "O", resp); //$NON-NLS-1$
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false);
	            			return;
	            		}
	                } else {
	            		if (ctx != null)
	            			ctx.authenticationFailure(u);
	                	error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
	                    logRecorder.addErrorLogEntry(u, Messages.getString("UserPasswordAction.8"), req.getRemoteAddr()); //$NON-NLS-1$
	                }
            	}
            } catch (UnknownUserException e) {
            	error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
            } catch (Exception e) {
                error = Messages.getString("UserPasswordAction.internal.error");
                String s = "";
                while (e != null) {
                	s = e.getClass().getSimpleName()+": "+e.getMessage();
                	if (e.getCause() == null || e.getCause() == e ||
                			! (e instanceof Exception))
                		break;
                	e = (Exception) e.getCause();
                }
                error += ": "+ s;
                LogFactory.getLog(getClass()).info("Error validating certificate ", e);
            }
        }
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }

}
