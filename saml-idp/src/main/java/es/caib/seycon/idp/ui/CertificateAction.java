package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.User;
import com.soffid.iam.service.OTPValidationService;

import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.ui.cred.ValidateCredential;
import es.caib.seycon.idp.ui.cred.ValidateUserPushCredentialServlet;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.ng.exception.InternalErrorException;

public class CertificateAction extends HttpServlet {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost(req, resp);
	}

	public static final String URI = "/certificateLoginAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }

        try {
            CertificateValidator v = new CertificateValidator();
            String certUser = null;
            try {
            	certUser = v.validate(req);
            } catch (Exception e) {
            	
            }
            if (certUser == null) {
        		req.setAttribute("ERROR", Messages.getString("SignatureAction.unrecognizedCertificate")); //$NON-NLS-1$ //$NON-NLS-2$
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        		if (ctx != null && ctx.getUser() != null)
        			ctx.authenticationFailure( ctx.getUser() , Messages.getString("SignatureAction.unrecognizedCertificate"));
            } else {
            	try {
            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            		if (!ctx.isFinished()) {
	            		ctx.authenticated(certUser, "C", resp);
	    				Date warning = IdpConfig.getConfig().getFederationService()
	    						.getCertificateExpirationWarning(Arrays.asList( v.getCerts(req) ));
	    				if (warning != null) 
	    					ctx.setCertificateWarning(warning);
	    				ctx.store(req);
            		}
            		
            		if ( ctx.isFinished())
            		{
            			if (ctx.getCertificateWarning() != null &&
            					!"true".equals(req.getParameter("confirm")))
            			{
            				generateWarningPage(req, resp, ctx);
            			} else {
	            			new Autenticator().autenticate2(certUser, getServletContext(),req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
            			}
            			return;
            		}
            	} catch (Exception e) {
        			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
                    LogFactory.getLog(getClass()).info("Error validating certificate ", e);
            	}
	        }
            IdpConfig config = IdpConfig.getConfig();
            if (req.getLocalPort() == config.getStandardPort())
            	resp.sendRedirect(UserPasswordFormServlet.URI);
            else
            	resp.sendRedirect( 
            			"https://"+config.getHostName()+":"+config.getStandardPort()+  //$NON-NLS-1$  //$NON-NLS-2$
            			UserPasswordFormServlet.URI);
        } catch (Exception e) {
			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
            LogFactory.getLog(getClass()).info("Error validating certificate ", e);
        }
        
    }

	private void generateWarningPage(HttpServletRequest req, HttpServletResponse resp, AuthenticationContext ctx) throws TextFormatException, IOException, ServletException {
        HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
        g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
        g.addArgument("refreshUrl", URI); //$NON-NLS-1$
        g.addArgument("kerberosUrl", NtlmAction.URI); //$NON-NLS-1$
        g.addArgument("passwordLoginUrl", UserPasswordAction.URI); //$NON-NLS-1$
        g.addArgument("userUrl", UserAction.URI); //$NON-NLS-1$
        g.addArgument("certificateLoginUrl", CertificateAction.URI); //$NON-NLS-1$
        g.addArgument("changeUserUrl", ChangeUserAction.URI); //$NON-NLS-1$
        g.addArgument("resendSmsUrl", ResendSmsAction.URI);
        g.addArgument("cancelUrl", CancelAction.URI); //$NON-NLS-1$
        g.addArgument("otpLoginUrl", OTPAction.URI); //$NON-NLS-1$
        g.addArgument("pushLoginUrl", ValidateUserPushCredentialServlet.URI); //$NON-NLS-1$
        g.addArgument("registerUrl", RegisterFormServlet.URI);
        g.addArgument("recoverUrl", PasswordRecoveryAction.URI);
        g.addArgument("facebookRequestUrl", OauthRequestAction.URI);
        g.addArgument("userReadonly", "true"); //$NON-NLS-1$
        g.addArgument("certAllowed",  "true"); //$NON-NLS-1$ //$NON-NLS-2$
        g.addArgument("passwordAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
        g.addArgument("userAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
        g.addArgument("cancelAllowed", "false");
    	g.addArgument("otpToken",  ""); //$NON-NLS-1$ //$NON-NLS-2$
    	g.addArgument("fingerprintRegister", "false");
    	g.addArgument("fingerprintEnforced", "false");
    	
		g.addArgument("otpAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
     	g.addArgument("pushAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
    	g.addArgument("externalAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$

       	g.addArgument("fingerprintAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
       	g.addArgument("kerberosEnforced", "false");
        g.addArgument("fingerprintLoginUrl", ValidateCredential.URI);
        g.addArgument("registerAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
        g.addArgument("recoverAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
        g.addArgument("externalLogin", "");
        Date w = ctx.getCertificateWarning();
        if (w != null) {
        	long days = (w.getTime() - System.currentTimeMillis()) / 1000 / 60 / 60 / 24; 
        	String msg = String.format(Messages.getString("certificateWarning"), days);
        	g.addArgument("certificateWarning", msg);
        }
   		g.generate(resp, "certificateWarning.html"); //$NON-NLS-1$
	}
    
   

}
