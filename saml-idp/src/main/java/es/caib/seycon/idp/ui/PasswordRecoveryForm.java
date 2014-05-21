package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.util.storage.StorageService;
import org.opensaml.xml.util.DatatypeHelper;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.FederacioService;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.InternalErrorException;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.textformatter.TextFormatter;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordRecoveryForm extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/passwordRecoveryForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$

        try {
        	
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$

            g.generate(resp, "recoverPage.html"); //$NON-NLS-1$

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
