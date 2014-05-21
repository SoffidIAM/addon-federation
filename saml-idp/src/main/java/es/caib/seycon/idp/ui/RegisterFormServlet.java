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

public class RegisterFormServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/registerForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    String emptyfy (Object obj)
    {
    	if (obj == null)
    		return "";
    	else
    		return obj.toString();
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$

        try {
        	
        	IdpConfig config = IdpConfig.getConfig();
        	
        	FederationMember ip = amf.getIdentityProvider();
        	if (ip == null || ! ip.isAllowRegister() || ip.getUserTypeToRegister() == null)
        		throw new ServletException ("Not authorized to self register");
        	
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("previousUserName", emptyfy( req.getAttribute("previousUserName"))); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("previousSurName", emptyfy( req.getAttribute("previousSurName"))); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("previousGivenName", emptyfy( req.getAttribute("previousGivenName"))); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("previousEmail", emptyfy( req.getAttribute("previousEmail"))); //$NON-NLS-1$ //$NON-NLS-2$

	        g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("registerUrl", RegisterAction.URI);
            g.addArgument("loginPage", UserPasswordFormServlet.URI);
            
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	String userType = ip.getUserTypeToRegister();
        	g.addArgument("policy", 
        			config.getFederationService().getPolicyDescriptionForUserType(userType, IdpConfig.getConfig().getDispatcher().getCodi()));

            g.generate(resp, "registerPage.html"); //$NON-NLS-1$

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
