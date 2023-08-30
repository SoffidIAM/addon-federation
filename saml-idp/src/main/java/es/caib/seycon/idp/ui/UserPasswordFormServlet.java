package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.User;
import com.soffid.iam.service.OTPValidationService;
import com.soffid.iam.utils.Security;

import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.broker.SAMLSSORequest;
import es.caib.seycon.idp.ui.cred.ValidateCredential;
import es.caib.seycon.idp.ui.cred.ValidateUserPushCredentialServlet;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class UserPasswordFormServlet extends BaseForm {
	static Log log = LogFactory.getLog(UserPasswordFormServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/passwordLoginForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        
        if (NtlmAction.URI.equals(req.getAttribute("javax.servlet.error.request_uri")))
        {
        	req.getSession().setAttribute("disableKerberos", Boolean.TRUE);
        	req.setAttribute("ERROR", Messages.getString("KerberosLogin.noToken"));
        }
        String requestedUser = "";
        String userReadonly = "dummy";
        AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        
        
        try {
        	if ( ctx != null && ctx.getStep() > 0 ) {
        		requestedUser = ctx.getUser();
        	}
        	else {
        		try {
	        		requestedUser = ((Saml2LoginContext)HttpServletHelper.getLoginContext(req))
						.getAuthenticiationRequestXmlObject()
						.getSubject()
						.getNameID()
						.getValue();
        		} catch (Exception e) {}
        		try {
        			if (requestedUser == null) {
	        	    	OpenIdRequest oidr =  (OpenIdRequest) req.getSession().getAttribute(SessionConstants.OPENID_REQUEST);
	        	    	if (oidr != null)
	        	    		requestedUser = oidr.getLoginHint();
        			}
        		} catch (Exception e) {}
        	}       		
        	if (requestedUser != null &&  !requestedUser.trim().isEmpty() &&
        			! ctx.isFinished() &&
        			forwardToIdp(requestedUser, req, resp))
        		return;
        	if (ctx.getUser() != null &&  !ctx.getUser().trim().isEmpty() && 
        			! ctx.isFinished() &&
        			forwardToIdp(ctx.getUser(), req, resp))
        		return;
 			if (requestedUser != null && ! requestedUser.trim().isEmpty())
				userReadonly = "readonly";
		} catch (Exception e1) {
			log.warn("Error guessing user idp", e1);
		}
        try {
            HttpSession session = req.getSession();
            IdpConfig config = IdpConfig.getConfig();
            
            String relyingParty = (String) session.
                    getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
            
            if (relyingParty == null) {
            	resp.sendRedirect("/logout.jsp");
            	return;
            }

        	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
            if (ip == null)
            	throw new es.caib.seycon.ng.exception.InternalErrorException(String.format("Internal error. Cannot guess virtual identity provider for %s", relyingParty));

        	log.info("Displaying login page");
        	log.info("Current user "+ctx.getUser());
        	if (ctx.getUser() != null) {
        		userReadonly = "readonly";
        		requestedUser = ctx.getUser();
        	}
        	log.info("Source ip address "+Security.getClientIp());
        	log.info("Authentication methods "+ctx.getAllowedAuthenticationMethods());
        	log.info("Authentication step "+ctx.getStep());
        	log.info("Next authentication factor "+ctx.getNextFactor());
            
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("enableCaptcha", Boolean.TRUE.equals(config.getFederationMember().getEnableCaptcha()) ? "true": "false");
            g.addArgument("captchaKey", config.getFederationMember().getCaptchaKey());
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
            g.addArgument("userReadonly", userReadonly); //$NON-NLS-1$
            g.addArgument("requestedUser", requestedUser);
            g.addArgument("kerberosAllowed", ctx.getNextFactor().contains("K") && session.getAttribute("disableKerberos") == null ? "true" : "false"); 
            g.addArgument("kerberosDomain", ip.getKerberosDomain());
            g.addArgument("certAllowed",  ctx.getNextFactor().contains("C") ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("passwordAllowed",  ctx.getNextFactor().contains("P") ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("userAllowed",  ctx.getNextFactor().contains("P") || 
            		ctx.getNextFactor().contains("Z") ||
            		ctx.getNextFactor().contains("O") ||
            		ctx.getNextFactor().contains("M") ||
            		ctx.getNextFactor().contains("I") ||
            		ctx.getNextFactor().contains("S") ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("cancelAllowed", "openid".equals(session.getAttribute("soffid-session-type")) ? "true": "false");
        	g.addArgument("otpToken",  ""); //$NON-NLS-1$ //$NON-NLS-2$
        	g.addArgument("fingerprintRegister", "false");
        	g.addArgument("fingerprintEnforced", "false");
        	
        	
            boolean otpAllowed = ctx.getNextFactor().contains("O") || ctx.getNextFactor().contains("S") || ctx.getNextFactor().contains("I") || ctx.getNextFactor().contains("M");
            if (otpAllowed && !requestedUser.trim().isEmpty())
            {
            	User user;
				try {
					user = new RemoteServiceLocator().getServerService().getUserInfo(requestedUser, config.getSystem().getName());
					OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
					
					Challenge ch = ctx.getChallenge();
					if (ch == null || ! isResendAvailable(ch)) {
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
					if (ch.getCardNumber() == null)
					{
						if ( ctx.getNextFactor().size() == 1)
						{
							g.addArgument("ERROR", Messages.getString("OTPAction.notoken")); //$NON-NLS-1$
						}
						g.addArgument("otpAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
					}
					else 
					{
						g.addArgument("resendSms", isResendAvailable(ch) ? "true": "false") ;
						g.addArgument("sendVoice", isAlterativeMethodAllowed(ch) ? "true": "false");
						g.addArgument("otpAllowed",  "true"); //$NON-NLS-1$ //$NON-NLS-2$
						g.addArgument("userAllowed", "true");
						g.addArgument("otpToken",  ch.getCardNumber()+" "+ch.getCell()); //$NON-NLS-1$ //$NON-NLS-2$
					}
				} catch (UnknownUserException e) {
	            	g.addArgument("otpAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
				}
            }
            else
            {
            	g.addArgument("otpAllowed",  otpAllowed ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            }
            
            boolean pushAllowed = ctx.getNextFactor().contains("Z");
            if (pushAllowed && !requestedUser.trim().isEmpty())
            {
            	User user;
				try {
					user = new RemoteServiceLocator().getServerService().getUserInfo(requestedUser, config.getSystem().getName());
					Collection<UserCredentialChallenge> ch = new RemoteServiceLocator().getPushAuthenticationService().sendPushAuthentication(user.getUserName());
					ctx.setPushChallenge(ch);
					g.addArgument("pushAllowed", ch.isEmpty() ? "false": "true");
				} catch (UnknownUserException e) {
	            	g.addArgument("pushAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
				}
            }
            else
            {
            	g.addArgument("pushAllowed",  "false"); //$NON-NLS-1$ //$NON-NLS-2$
            }
        	g.addArgument("externalAllowed", ctx.getNextFactor().contains("E") ? "true": "false"); //$NON-NLS-1$ //$NON-NLS-2$

            if (ctx.getNextFactor().contains("F") && !requestedUser.trim().isEmpty())
            {
            	try {
	            	User user = new RemoteServiceLocator().getServerService().getUserInfo(requestedUser, config.getSystem().getName());
	            	StringBuffer sb = new StringBuffer();
	            	for (UserCredential cred: new RemoteServiceLocator().getUserCredentialService().findUserCredentials(user.getUserName())) {
	            		if (cred.getType() == UserCredentialType.FIDO &&
	            				cred.getRawid() != null) {
	            			if (sb.length() > 0)
	            				sb.append(",");
	            			sb.append("\"").append(cred.getRawid()).append("\"");
	            		}
	            	}
	            	if (sb.length() > 0) {
		            	g.addArgument("fingerprintAllowed", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		            	String random = (String) session.getAttribute("fingerprintChallenge");
		            	if (random == null)
		            	{
		            		random = IdpConfig.getConfig().getUserCredentialService().generateChallenge();
		            		session.setAttribute("fingerprintChallenge", random);
		            	}
		            	g.addArgument("userAllowed", "true");
		            	g.addArgument("fingerprintChallenge", random);
		            	g.addArgument("fingerprintRawIds", sb.toString());
		            	if (ctx.getNextFactor().size() == 1)
		            		g.addArgument("fingerprintEnforced", "true");
	            	}
				} catch (UnknownUserException e) {
				}
            }
            else
            	g.addArgument("fingerprintAllowed", "false"); //$NON-NLS-1$ //$NON-NLS-2$
            
            if (ctx.getNextFactor().contains("K") && ctx.getNextFactor().size() == 1) {
            	g.addArgument("kerberosEnforced", "true");
            } else {
            	g.addArgument("kerberosEnforced", "false");
            }

            String s = (String) session.getAttribute("serialCredentialToRemove");
            if (s == null)
            	g.addArgument("fingerprintToRemove", "");
            else
            	g.addArgument("fingerprintToRemove", s);
            g.addArgument("fingerprintLoginUrl", ValidateCredential.URI);
            g.addArgument("registerAllowed", ip.isAllowRegister() ? "true" : "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("recoverAllowed", ip.isAllowRecover()? "true": "false"); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("externalLogin", generateExternalLogin(ip, ctx));
        	if ( ctx.getStep() > 0 || ctx.getUser() != null)
        		g.generate(resp, "loginPage2.html"); //$NON-NLS-1$
        	else
        		g.generate(resp, "loginPage.html"); //$NON-NLS-1$
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

	protected boolean isAlterativeMethodAllowed(Challenge ch) {
		try {
			return Boolean.TRUE.equals( ch.getClass().getMethod("isAlternativeMethodAvailable").invoke(ch) );
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException
				| SecurityException e) {
			return false;
		}
	}

	protected boolean isResendAvailable(Challenge ch) {
		try {
			return Boolean.TRUE.equals( ch.getClass().getMethod("isResendAvailable").invoke(ch) );
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException
				| SecurityException e) {
			return false;
		}
	}

    private boolean forwardToIdp(String requestedUser, HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException, InternalErrorException {
    	String idp = null;
		try {
			idp = new RemoteServiceLocator().getFederacioService().searchIdpForUser(requestedUser);
		} catch (InternalErrorException | IOException e) {
			LogFactory.getLog(getClass()).warn("Error guessing identity provider for "+requestedUser, e);
		}
    	if (idp != null) {
    		RequestDispatcher d;
    		FederationMember data = new RemoteServiceLocator().getFederacioService().findFederationMemberByPublicId(idp);
    		if ( data.getIdpType() == IdentityProviderType.SAML ||
    				(data.getIdpType() == IdentityProviderType.SOFFID))
    			d = req.getRequestDispatcher(SAMLSSORequest.URI);
    		else
    			d = req.getRequestDispatcher(OauthRequestAction.URI);
    		
    		d.forward(new SamlSsoRequestWrapper(req, requestedUser, idp), resp);
    		return true;
    	} else {
    		return false;
    	}
	}

	private String generateExternalLogin(FederationMember ip, AuthenticationContext ctx) throws InternalErrorException, IOException {
    	if ( ! ctx.getNextFactor().contains("E"))
    		return "";
    	
    	StringBuffer options = new StringBuffer();
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
    	if (options.length() > 0)
    	{
    		String className = ctx.getUser() == null ? "logintype": "logintype2";
			options.insert(0, "<div class=\""+className+"\"  id =\"otherlogin\"><ul>");
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
