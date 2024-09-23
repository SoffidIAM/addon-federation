package es.caib.seycon.idp.ui.cred;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.CancelAction;
import es.caib.seycon.idp.ui.CertificateAction;
import es.caib.seycon.idp.ui.HtmlGenerator;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.NtlmAction;
import es.caib.seycon.idp.ui.OTPAction;
import es.caib.seycon.idp.ui.PasswordRecoveryAction;
import es.caib.seycon.idp.ui.RegisterFormServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.idp.ui.UserPasswordAction;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;

public class ProtectedUserCredentialRegisterServlet extends BaseForm {
	static Log log = LogFactory.getLog(ProtectedUserCredentialRegisterServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/protected/registerCredential"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);


        try {
            HttpSession session = req.getSession();
            
            String user = (String) session.getAttribute(SessionConstants.SEU_USER); //$NON-NLS-1$
            if (user == null) {
                throw new ServletException(Messages.getString("PasswordChangeForm.expired.session")); //$NON-NLS-1$
            }

            req.getSession().setAttribute("$soffid$fido_request", null);
            IdpConfig config = IdpConfig.getConfig();
            
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("kerberosUrl", NtlmAction.URI); //$NON-NLS-1$
            g.addArgument("passwordLoginUrl", UserPasswordAction.URI); //$NON-NLS-1$
            g.addArgument("certificateLoginUrl", CertificateAction.URI); //$NON-NLS-1$
            g.addArgument("cancelUrl", CancelAction.URI); //$NON-NLS-1$
            g.addArgument("otpLoginUrl", OTPAction.URI); //$NON-NLS-1$
            g.addArgument("registerUrl", RegisterFormServlet.URI);
            g.addArgument("recoverUrl", PasswordRecoveryAction.URI);
            g.addArgument("facebookRequestUrl", OauthRequestAction.URI);
            g.addArgument("passwordAllowed", "true"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("userReadonly", "readonly"); //$NON-NLS-1$
            g.addArgument("requestedUser", user);
            g.addArgument("kerberosAllowed", "false"); 
            g.addArgument("kerberosDomain", null);
            g.addArgument("certAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("passwordAllowed",   "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("cancelAllowed", "false");
            g.addArgument("closeAllowed", "true");
        	g.addArgument("otpToken",  ""); //$NON-NLS-1$ //$NON-NLS-2$
        	g.addArgument("fingerprintRegister", "true");
           	g.addArgument("otpAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
           	g.addArgument("fingerprintAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
        	String random = (String) session.getAttribute("fingerprintChallenge");
        	if (random == null)
        	{
        		random = IdpConfig.getConfig().getUserCredentialService().generateChallenge();
        		session.setAttribute("fingerprintChallenge", random);
        	}
        	g.addArgument("fingerprintRegister", "true");
        	g.addArgument("fingerprintRegisterUrl", ProtectedValidateRegisteredCredential.URI);
        	g.addArgument("fingerprintEnforced", "false");
        	g.addArgument("kerberosEnforced", "false");
        	g.addArgument("fingerprintChallenge", random);
            g.addArgument("fingerprintLoginUrl", ProtectedValidateRegisteredCredential.URI);
            g.addArgument("registerAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("recoverAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("externalLogin", "");
       		g.generate(resp, "loginPage2.html"); //$NON-NLS-1$
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }


	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
