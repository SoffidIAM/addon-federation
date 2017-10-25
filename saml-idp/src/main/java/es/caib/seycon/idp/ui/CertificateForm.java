package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.idp.ui.openid.OpenIdRequestAction;

public class CertificateForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/certificateLoginForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }



    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
            if (! amf.allowTls())
                throw new ServletException (Messages.getString("CertificateForm.authenticationMethodNotAllowed")); //$NON-NLS-1$
            HttpSession session = req.getSession();
            IdpConfig config = IdpConfig.getConfig();
 
            String relyingParty = (String) session.
                    getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
            
            if (relyingParty == null)
            	throw new es.caib.seycon.ng.exception.InternalErrorException("Internal error. Cannot guess relying party");


        	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
            if (ip == null)
            	throw new es.caib.seycon.ng.exception.InternalErrorException(String.format("Internal error. Cannot guess virtual identity provider for %s", relyingParty));

            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("passwordLoginUrl", UserPasswordAction.URI); //$NON-NLS-1$
            g.addArgument("certificateLoginUrl", CertificateAction.URI); //$NON-NLS-1$
            g.addArgument("registerUrl", RegisterFormServlet.URI);
            g.addArgument("recoverUrl", PasswordRecoveryAction.URI);
            g.addArgument("openIdRequestUrl", OpenIdRequestAction.URI);
            g.addArgument("facebookRequestUrl", OauthRequestAction.URI);
            g.addArgument("passwordAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
          
            g.addArgument("certAllowed", ip.isAllowCertificate() ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("registerAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("recoverAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.generate(resp, "loginPage.html"); //$NON-NLS-1$
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
