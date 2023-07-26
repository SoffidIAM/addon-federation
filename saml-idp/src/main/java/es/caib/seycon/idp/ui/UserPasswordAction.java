package es.caib.seycon.idp.ui;

import java.io.IOException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.Password;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.server.CaptchaVerifier;
import es.caib.seycon.idp.server.CreateIssueHelper;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class UserPasswordAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static Log log = LogFactory.getLog(UserPasswordFormServlet.class);

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/passwordLoginAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        String u = req.getParameter("j_username"); //$NON-NLS-1$
        String p = req.getParameter("j_password"); //$NON-NLS-1$
        String error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
        if (u == null && ctx != null)
        	u = ctx.getUser();
        if (u == null || u.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.user.name"); //$NON-NLS-1$
        } else if ( p == null || p.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.password"); //$NON-NLS-1$
        } else {
            PasswordManager v = new PasswordManager();

            try {
            	FederationMember idp = IdpConfig.getConfig().getFederationMember();
            	if (Boolean.TRUE.equals(idp.getEnableCaptcha())) {
            		CaptchaVerifier captcha = new CaptchaVerifier();
            		if (! captcha.verify(req, idp, req.getParameter("captchaToken"))) {
            			LogFactory.getLog(getClass()).warn("Trying to authenticate user "+u+" from a page with low captcha score "+captcha.getConfidence());
                		error = "There seems to be problems to identify you, please, try again"; //$NON-NLS-1$
                        req.setAttribute("ERROR", error); //$NON-NLS-1$
                        if (ctx == null) {
                        	ctx = new AuthenticationContext();
                        	ctx.initialize(req);
                        }
                        try {
                        	CreateIssueHelper.robotLogin(u, captcha.getConfidence(),
                        		ctx.getHostId(resp), ctx.getRemoteIp());
                        } catch (Error e) {}
        				RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        				dispatcher.forward(req, resp);
        				return;
            		}
            	}
    			if ( ctx != null && ctx.isFinished())
    			{
    				new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
    				return;
    			}
                if (v.validate(u, new Password(p))) {
                	if (ctx == null) {
                		error = "Session timeout"; //$NON-NLS-1$
                		LogFactory.getLog(getClass()).info("Error authenticating user.  "+u+". Session timeout");
                	} else {
                		if (ctx.isLocked(u)) {
                    		error = "Account is locked"; //$NON-NLS-1$
                    		LogFactory.getLog(getClass()).info("Error authenticating user.  "+u+". Account is locked");
        	    			try {
        						ctx.authenticationFailure(u, "Account is locked");
        					} catch (InternalErrorException e) {
        					}
                		}
                		else if (v.mustChangePassword()) {
	                        logRecorder.addErrorLogEntry(u, Messages.getString("UserPasswordAction.7"), req.getRemoteAddr()); //$NON-NLS-1$
	                        HttpSession s = req.getSession();
	                        s.setAttribute(SessionConstants.SEU_TEMP_USER, u);
	                        s.setAttribute(SessionConstants.SEU_TEMP_PASSWORD, new Password(p));
	                        RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
	                        dispatcher.forward(req, resp);
	                        return;
	                    } else {
	            			ctx.authenticated(u, "P", resp);
	            			ctx.store(req);
	            			if ( ctx.isFinished())
	            			{
	            				new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
	            				return;
	            			}
	            			else
	            			{
	            				RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
	            				dispatcher.forward(req, resp);
	            				return;
	            			}
	            		}
                    }
                } else {
    	    		if (ctx != null)
    	    		{
    	    			try {
		                  ctx.authenticationFailure(u, "Wrong user name or password");
		                  if (ctx.isLocked(u)) {
		                    LogFactory.getLog(getClass()).info("Error authenticating user.  "+u+". Account is locked");
		                  }
		                } catch (InternalErrorException e) {
		                  // Account is disabled
		                }
    	    		}
                    logRecorder.addErrorLogEntry(u, Messages.getString("UserPasswordAction.8"), req.getRemoteAddr()); //$NON-NLS-1$
                }
            } catch (UnknownUserException e) {
            } catch (Exception e) {
                error = Messages.getString("UserPasswordAction.internal.error"); //$NON-NLS-1$
                LogFactory.getLog(getClass()).info("Error authenticating user "+u, e);
            }
        }
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }

}
