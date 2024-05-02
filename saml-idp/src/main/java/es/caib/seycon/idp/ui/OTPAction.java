package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.ClassNotFoundException;
import java.lang.NoSuchMethodException;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.OTPValidationService;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.server.CaptchaVerifier;
import es.caib.seycon.idp.server.CreateIssueHelper;
import es.caib.seycon.idp.session.SessionChecker;
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
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        
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
                String entityId = (String) req.getSession()
                		.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
            	FederationMember idp = IdpConfig.getConfig().findIdentityProviderForRelyingParty(entityId);
            	if (Boolean.TRUE.equals(idp.getEnableCaptcha())) {
            		CaptchaVerifier captcha = new CaptchaVerifier();
            		if (! captcha.verify(req, idp, req.getParameter("captchaToken"))) {
            			LogFactory.getLog(getClass()).warn("Trying to authenticate user "+u+" from a page with low captcha score "+captcha.getConfidence());
                		error = "There seems to be problems to identify you, please, try again"; //$NON-NLS-1$
                        req.setAttribute("ERROR", error); //$NON-NLS-1$
                        try {
                        	CreateIssueHelper.robotLogin(u, captcha.getConfidence(),
                        			ctx.getHostId(resp), ctx.getRemoteIp());
                        } catch (Error e ) {}
        				RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        				dispatcher.forward(req, resp);
        				return;
            		}
            	}
            	OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
            	IdpConfig config = IdpConfig.getConfig();
            	
            	User user = new RemoteServiceLocator().getServerService().getUserInfo(u, config.getSystem().getName());
            	
            	if (user == null) {
            		error = Messages.getString("OTPAction.notoken"); //$NON-NLS-1$
                    logRecorder.addErrorLogEntry(getSessionType(req), u, 
                    		"NOOTP: "+error,
                    		entityId,
                    		ctx.getHostId(resp), req.getRemoteAddr()); //$NON-NLS-1$
                    try {
                    	CreateIssueHelper.wrongUser(u,
                    		ctx.getHostId(resp), ctx.getRemoteIp());
                    } catch (Error e) {}
            	} else {
	            	Challenge ch = ctx.getChallenge();
	            	if (ch == null ||  ch.getCardNumber() == null) {
						ch = new Challenge();
						ch.setUser(user);
						StringBuffer otpType = new StringBuffer();
						if (ctx.getNextFactor().contains("O")) otpType.append("OTP ");
						if (ctx.getNextFactor().contains("M")) otpType.append("EMAIL ");
						if (ctx.getNextFactor().contains("I")) otpType.append("PIN ");
						if (ctx.getNextFactor().contains("S")) otpType.append("SMS ");
						ch.setOtpHandler(otpType.toString());
						ch = v.selectToken(ch);
						ctx.setChallenge(ch);
	            	}
	            	if (ch == null && ch.getCardNumber() == null)
	            	{
	            		error = Messages.getString("OTPAction.notoken"); //$NON-NLS-1$
	                    logRecorder.addErrorLogEntry(getSessionType(req), u,
	                    		"NOOTP: "+error, 
	                    		entityId,
	                    		ctx.getHostId(resp), req.getRemoteAddr()); //$NON-NLS-1$
	            	}
	            	else if (v.validatePin(ch, p)) {
	            		String auditType = null;
	            		try {
	            			Class<?> c = v.getClass();
	            			Method m = c.getMethod("generateTypeForAudit", Challenge.class);
	            			auditType = (String) m.invoke(v, ch);
	            		} catch (Exception e) {}

	            		if (auditType==null) {
		            		Set<String> nf = ctx.getNextFactor();
		            		if (nf.contains("I"))
		            			auditType = "I"; //$NON-NLS-1$
		            		else if (nf.contains("S"))
		            			auditType = "S"; //$NON-NLS-1$
		            		else if (nf.contains("M"))
		            			auditType = "M"; //$NON-NLS-1$
		            		else if (nf.contains("O"))
		            			auditType = "O"; //$NON-NLS-1$
	            		}

	            		ctx.setChallenge(null);
	            		ctx.authenticated(u, auditType, resp); //$NON-NLS-1$
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
	            			return;
	            		}
	            	} else if (ctx.isFinished()) { // User has pressed the login button twice
            			new Autenticator().autenticate2(u, getServletContext(),req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
            			return;
	                } else {
	            		if (ctx != null)
	            			ctx.authenticationFailure(u, Messages.getString("UserPasswordAction.wrong.password"));
	                	error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
	                    logRecorder.addErrorLogEntry(getSessionType(req), u, 
	                    		"WRONGOTP: "+Messages.getString("UserPasswordAction.8"),
	                    		entityId,
	                    		ctx.getHostId(resp),
	                    		req.getRemoteAddr()); //$NON-NLS-1$
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

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        req.setAttribute("ERROR", ""); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }
    
	protected String getSessionType(HttpServletRequest req) {
		HttpSession session = req.getSession(false);
		if (session == null)
			return "wsso";
        String sessionType = (String) session.getAttribute("soffid-session-type");
        if (sessionType == null)
        	return "wsso";
        else
        	return sessionType.toUpperCase();
	}

}
