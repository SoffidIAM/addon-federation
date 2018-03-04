package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.util.storage.StorageService;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.broker.SAMLSSORequest;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.idp.ui.openid.OpenIdRequestAction;
import es.caib.seycon.ng.exception.InternalErrorException;

public class UserPasswordFormServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/passwordLoginForm"; //$NON-NLS-1$
    private ServletContext context;
    private IdPProfileHandlerManager handlerManager;
    private SessionManager<Session> sessionManager;
    private StorageService<String, LoginContextEntry> storageService;
    private RelyingPartyConfigurationManager relyingPartyConfigurationManager;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
        handlerManager = HttpServletHelper.getProfileHandlerManager(context);
        sessionManager = HttpServletHelper.getSessionManager(context);
        relyingPartyConfigurationManager = HttpServletHelper.getRelyingPartyConfigurationManager(context);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        String requestedUser = "";
        String userReadonly = "dummy";
        try {
			requestedUser = ((Saml2LoginContext)HttpServletHelper.getLoginContext(req))
					.getAuthenticiationRequestXmlObject()
					.getSubject()
					.getNameID()
					.getValue();
			if (requestedUser != null && ! requestedUser.trim().isEmpty())
				userReadonly = "readonly";
		} catch (Exception e1) {
		}
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$

        try {
            HttpSession session = req.getSession();
            IdpConfig config = IdpConfig.getConfig();
            
            String relyingParty = (String) session.
                    getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
            
            if (relyingParty == null)
            	throw new es.caib.seycon.ng.exception.InternalErrorException("Internal error. Cannot guess relying party");

        	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
            if (ip == null)
            	throw new es.caib.seycon.ng.exception.InternalErrorException(String.format("Internal error. Cannot guess virtual identity provider for %s", relyingParty));

            Collection<FederationMember> vip = ip.getVirtualIdentityProvider();
            
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("kerberosUrl", NtlmAction.URI); //$NON-NLS-1$
            g.addArgument("passwordLoginUrl", UserPasswordAction.URI); //$NON-NLS-1$
            g.addArgument("certificateLoginUrl", CertificateAction.URI); //$NON-NLS-1$
            g.addArgument("registerUrl", RegisterFormServlet.URI);
            g.addArgument("recoverUrl", PasswordRecoveryAction.URI);
            g.addArgument("openIdRequestUrl", OpenIdRequestAction.URI);
            g.addArgument("facebookRequestUrl", OauthRequestAction.URI);
            g.addArgument("passwordAllowed", "true"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("userReadonly", userReadonly); //$NON-NLS-1$
            g.addArgument("requestedUser", requestedUser);

            g.addArgument("kerberosAllowed", 
            		ip.getEnableKerberos() != null && 
            		ip.getEnableKerberos().booleanValue()
            		 ? "true": "false"); //$NON-NLS-1$ //$NON-NLS-2$
          
            g.addArgument("kerberosDomain", ip.getKerberosDomain());
            g.addArgument("certAllowed", ip.isAllowCertificate() ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("registerAllowed", ip.isAllowRegister() ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("recoverAllowed", ip.isAllowRecover()? "true": "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("externalLogin", generateExternalLogin(ip));
            g.generate(resp, "loginPage.html"); //$NON-NLS-1$
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

    private String generateExternalLogin(FederationMember ip) throws InternalErrorException, IOException {
    	if (ip.getIdentityBroker() != null && ! ip.getIdentityBroker().booleanValue())
    		return "";
    	
    	StringBuffer options = new StringBuffer();
    	if (ip.getEnableKerberos().booleanValue())
    		options.append("<li><a class=\"openidlink\" href=\""+NtlmAction.URI+"\"><img class=\"openidbutton\" src=\"/img/kerberos.png\"></img></a></li>");
    	if (ip.getIdentityBroker() != null && ip.getIdentityBroker().booleanValue())
    	{
	    	for (FederationMember fm: new RemoteServiceLocator().getFederacioService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "I"))
	    	{
	    		if (! fm.getInternal().booleanValue() && 
	    				(fm.getDomainExpression() == null || fm.getDomainExpression().trim().isEmpty()))
	    		{
	    			if (fm.getIdpType().equals(IdentityProviderType.GOOGLE))
	    			{
	    				options.append("<li><a class=\"openidlink\" href=\"" + OauthRequestAction.URI+"?id="+fm.getPublicId()+"\">"
	    						+ "<img class=\"openidbutton\" src=\"/img/google.png\"></img></a></li>"); 
	    				
	    			}
	    			else if (fm.getIdpType().equals(IdentityProviderType.FACEBOOK))
	    			{
	    				options.append("<li><a class=\"openidlink\" href=\"" + OauthRequestAction.URI+"?id="+fm.getPublicId()+"\">"
	    						+ "<img class=\"openidbutton\" src=\"/img/facebook.png\"></img></a></li>"); 
	    				
	    			}
	    			else if (fm.getIdpType().equals(IdentityProviderType.LINKEDIN))
	    			{
	    				options.append("<li><a class=\"openidlink\" href=\"" + OauthRequestAction.URI+"?id="+fm.getPublicId()+"\">"
	    						+ "<img class=\"openidbutton\" src=\"/img/linkedin.png\"></img></a></li>"); 
	    				
	    			}
	    			else if (fm.getIdpType().equals(IdentityProviderType.SAML))
	    			{
	    				options.append("<li><a class=\"openidlink\" href=\"" + SAMLSSORequest.URI+"?idp="+fm.getPublicId()+"\">"
	    						+  fm.getName()+"</a></li>"); 
	    				
	    			}
	    			else if (fm.getIdpType().equals(IdentityProviderType.OPENID_CONNECT))
	    			{
	    				options.append("<li><a class=\"openidlink\" href=\"" + OauthRequestAction.URI+"?id="+fm.getPublicId()+"\">"
	    						+  fm.getName()+"</a></li>"); 
	    				
	    			}
	    		}
	    	}
    	}
    	if (options.length() > 0)
    	{
			options.insert(0, "<div class=\"logintype\"  id =\"otherlogin\"><ul>");
    		options.append("</ul></div>");
    	}
    	return options.toString();
	}

	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
