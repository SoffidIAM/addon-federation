package es.caib.seycon.idp.ui;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
            	
            	Challenge ch = new Challenge();
            	ch.setUser(user);
            	ch = v.selectToken(ch);
            	if (ch.getCardNumber() == null)
            	{
            		error = Messages.getString("OTPAction.notoken"); //$NON-NLS-1$
                    logRecorder.addErrorLogEntry(u, error, req.getRemoteAddr()); //$NON-NLS-1$
            	}
            	else if (v.validatePin(ch, p)) {
            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            		ctx.authenticated(u, "O"); //$NON-NLS-1$
            		ctx.store(req);
            		if ( ctx.isFinished())
            		{
            			new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false);
            			return;
            		}
                } else {
                	error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
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
