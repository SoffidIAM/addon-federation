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
import org.apache.http.auth.AUTH;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.service.OtpService;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.Password;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.server.CaptchaVerifier;
import es.caib.seycon.idp.server.CreateIssueHelper;
import es.caib.seycon.idp.server.RoleRestrictionException;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class RegisterOtpAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	static Log log = LogFactory.getLog(UserPasswordFormServlet.class);

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/registerOtpAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        
        OtpDevice device = ctx.getOtpDeviceToRegister();
        String pin = req.getParameter("pin");
        String error = null;
        try {
	        if (device != null && pin != null)  {
	    		OtpService svc = (OtpService) new RemoteServiceLocator().getRemoteService(OtpService.REMOTE_PATH);
	    		if (svc.validateChalleng(device, pin)) {
	    			device.setStatus(OtpStatus.VALIDATED);
	    			svc.updateDevice(device);
            		ctx.setChallenge(null);
            		String auditType = device.getType() == OtpDeviceType.EMAIL ? "M" :
            			device.getType() == OtpDeviceType.HOTP ? "O":
            			device.getType() == OtpDeviceType.TOTP ? "O":
               			device.getType() == OtpDeviceType.PIN ? "I":
                    	device.getType() == OtpDeviceType.SMS ? "S":
                        device.getType() == OtpDeviceType.PUSH ? "Z" :
                        					"P";
            		ctx.authenticated(ctx.getUser(), auditType, resp); //$NON-NLS-1$
            		ctx.store(req);
            		if ( ctx.isFinished())
            		{
            			new Autenticator().autenticate2(ctx.getUser(), 
            						getServletContext(),req, resp, 
            						ctx.getUsedMethod(), 
	            					ctx.getLevelOfAssurance(),
	            					false, 
            						ctx.getHostId(resp));
            			return;
            		}
	    		} else {
	    			error = Messages.getString("UserPasswordAction.wrong.password");
	    		}
	        }
        
        } catch (RoleRestrictionException e) {
            error = Messages.getString("SystemAccessRestricted"); //$NON-NLS-1$
            LogFactory.getLog(getClass()).info("Error authenticating new token "+ctx.getUser(), e);
        } catch (Exception e) {
            error = Messages.getString("UserPasswordAction.internal.error"); //$NON-NLS-1$
            LogFactory.getLog(getClass()).info("Error authenticating new token "+ctx.getUser(), e);
        }
        req.setAttribute("ERROR", error); //$NON-NLS-1$
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
