package es.caib.seycon.idp.server;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.config.Config;
import com.soffid.iam.federation.idp.LanguageFilter;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.sync.service.ServerService;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.AuthorizationResponse;
import es.caib.seycon.idp.session.SessionCallbackServlet;
import es.caib.seycon.idp.session.SessionListener;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.shibext.SessionPrincipal;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.util.Base64;

public class Autenticator {
    private static final Logger LOG = LoggerFactory.getLogger(Autenticator.class);

    private String generateSession2 (HttpServletRequest req, HttpServletResponse resp, String principal, String type, boolean externalAuth) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, UnknownUserException
    {
        HttpSession session = req.getSession();
        ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        
        IdpConfig config = IdpConfig.getConfig();
        
        User user = server.getUserInfo(principal, config.getSystem().getName());
        
        server.updateExpiredPasswords(user, externalAuth);
        
        String url = "https://" + config.getHostName()+":"+config.getStandardPort()+ SessionCallbackServlet.URI;
        
        com.soffid.iam.api.Session sessio = new RemoteServiceLocator().getSessionService().registerWebSession(
        		user.getUserName(), config.getHostName(),
        		LanguageFilter.getRemoteIp(),
        		url, type);

        SessionListener.registerSession(session, sessio.getId().toString());
        
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(SeyconKeyStore.getKeyStoreFile()),
        		SeyconKeyStore.getKeyStorePassword().getPassword().toCharArray());

        Certificate cert = ks.getCertificate(SeyconKeyStore.ROOT_CERT);
        String certString = Base64.encodeBytes(cert.getEncoded());
        
        Config serverConfig = Config.getConfig();

        StringBuffer buffer = new StringBuffer ();
        buffer.append (sessio.getId()).append("|").append(sessio.getKey()).
        	append("|").
        	append (certString).append("|").
        	append(serverConfig.getServerList());
        
        setCookie2 (req, resp, sessio, user, type);
        return buffer.toString();
    }
    
    public boolean validateCookie (ServletContext ctx, HttpServletRequest req, HttpServletResponse resp) 
    		throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException, UnknownUserException, ServletException
    {
        HttpSession session = req.getSession();
        IdpConfig config = IdpConfig.getConfig();
        
        String relyingParty = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        
        if (relyingParty == null){
			return false;
		}

    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
        if (ip == null){
			return false;
		}
    	
        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0)
        {
        	for (Cookie c: req.getCookies())
        	{
        		if (c.getName().equals(ip.getSsoCookieName()))
        		{
    				if (checkExternalCookie(ctx, req, resp, config, c) || 
    						checkOwnCookie(ctx, req, resp, config, c))
    					return true;
        		}
        	}
        }
        return false;
    }

	private boolean checkExternalCookie(ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, IdpConfig config, Cookie c) 
			throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, UnknownUserException, ServletException {
		String value = c.getValue();
		FederacioService fs = new RemoteServiceLocator().getFederacioService();
		SamlValidationResults check = fs.validateSessionCookie(value);
		if (check.isValid() && check.getUser() != null)
		{
			Collection<UserAccount> accounts = new com.soffid.iam.remote.RemoteServiceLocator()
					.getServerService()
					.getUserAccounts(check.getUser().getId(), config.getSystem().getName());
			if (accounts == null || accounts.isEmpty())
			{
			}
			else
			{
				String user = accounts.iterator().next().getName();
		        String requestedUser = "";
		        try {
					requestedUser = ((Saml2LoginContext)HttpServletHelper.getLoginContext(req))
							.getAuthenticiationRequestXmlObject()
							.getSubject()
							.getNameID()
							.getValue();
				} catch (Exception e1) {
				}
		        if (! requestedUser.isEmpty() && !user.equals(requestedUser))
		        {
		            HttpSession session = req.getSession();
		            session.removeAttribute(SessionConstants.SEU_USER);
		            return false;
		        }
		        else {
		        	autenticate2(user, ctx, req, resp, "E", true);
		        }
				return true;
			}
		}
		return check.isValid();
	}

	private boolean checkOwnCookie(ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, IdpConfig config, Cookie c) throws InternalErrorException, IOException, NoSuchAlgorithmException,
			UnsupportedEncodingException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException,
			CertificateException, NoSuchProviderException, SignatureException, IllegalStateException, ServletException {
		String value = c.getValue();
		int separator = value.indexOf('_');
		if (separator > 0)
		{
			String hash = value.substring(separator+1);
			Long id = Long.decode(value.substring(0, separator));
			for (Session sessio: new RemoteServiceLocator().getSessionService().getActiveSessions(id))
			{
				byte digest[] = MessageDigest.getInstance("SHA-1").digest(sessio.getKey().getBytes("UTF-8"));
				String digestString = Base64.encodeBytes(digest);
				if (digestString.equals(hash))
				{
					try {
						
						ServerService svc = new RemoteServiceLocator().getServerService();
						User u = svc.getUserInfo(sessio.getUserName(), null);
						if (u != null && u.getActive().booleanValue())
						{
							for (UserAccount account: svc.getUserAccounts(u.getId(), config.getSystem().getName()))
							{
								autenticate2(account.getName(), ctx, req, resp,  
										sessio.getAuthenticationMethod() == null ? "E" : sessio.getAuthenticationMethod(), 
										true);
				        		return true;
							}
						}
					} catch (UnknownUserException e) {
						e.printStackTrace();
					}
				}
				
			}
		}
		return false;
	}
    

    private void setCookie2(HttpServletRequest req, HttpServletResponse resp,
			Session sessio, User user, String type) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
        HttpSession session = req.getSession();
        IdpConfig config = IdpConfig.getConfig();
        
        String relyingParty = (String) session.
                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        
        if (relyingParty == null)
        	throw new es.caib.seycon.ng.exception.InternalErrorException("Internal error. Cannot guess relying party");

    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
        if (ip == null)
        	throw new es.caib.seycon.ng.exception.InternalErrorException(String.format("Internal error. Cannot guess virtual identity provider for %s", relyingParty));

        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0)
        {
        	byte digest[] = MessageDigest.getInstance("SHA-1").digest(sessio.getKey().getBytes("UTF-8"));
        	String digestString = Base64.encodeBytes(digest);
        	String value = user.getId().toString()+"_"+digestString;
        	Cookie cookie = new Cookie(ip.getSsoCookieName(), value);
//        	cookie.setMaxAge(-1);
        	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
        		cookie.setDomain(ip.getSsoCookieDomain());
        	resp.addCookie(cookie);
        	if (type != null && type.contains("K"))
        	{
        		Cookie cookie2 = new Cookie (ip.getSsoCookieName()+"_krb", "true");
        		cookie2.setMaxAge(60 * 24 * 3); // 3 monthis to remember kerberos usage
            	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
            		cookie2.setDomain(ip.getSsoCookieDomain());
            	resp.addCookie(cookie2);
        	}
        }
	}

    
    public String getUserAccount (String user) throws InternalErrorException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException
    {
    	String dispatcher = IdpConfig.getConfig().getSystem().getName();
    	for ( UserAccount account: new RemoteServiceLocator().getAccountService().findUsersAccounts(user, dispatcher))
    	{
    		if (! account.isDisabled())
    			return account.getName();
    	}
    	throw new InternalErrorException("Not authorized to log in");
    }
    
	public void autenticate2 (String user, ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, String type, boolean externalAuth) throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException, ServletException {
    	autenticate2(user, ctx, req, resp, type, type, externalAuth);
    }
    
    public void autenticate2 (String user, ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, String type, String actualType, boolean externalAuth) throws IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, UnknownUserException, ServletException {

        LOG.info("Remote user identified as "+user+". returning control back to authentication engine"); //$NON-NLS-1$ //$NON-NLS-2$

        HttpSession session = req.getSession();
        
        String entityId = (String) session
        		.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        session.setAttribute(SessionConstants.SEU_USER, user);
		AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
		if (authCtx == null)
		{
			authCtx = new AuthenticationContext();
			authCtx.setPublicId(entityId);
			authCtx.initialize();
		}
		authCtx.setFirstFactor(type.substring(0, 1));
		authCtx.setSecondFactor(type.substring(1));
		authCtx.setStep(2);
		authCtx.setUser(user);
		authCtx.store(req);

        if ("saml".equals(session.getAttribute("soffid-session-type")))
        {
	        String returnPath = (String) session.getAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
	
	        Principal principal = new SessionPrincipal(user, 
	        		generateSession2(req, resp, user, type, externalAuth));
	        
	        req.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
	        req.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY,  toSamlAuthenticationMethod(type));
	        req.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, user);
	        Set<Principal> principals = new HashSet<Principal> ();
	        Set<?> pubCredentals = new HashSet<Object>();
	        Set<?> privCredentials = new HashSet<Object>();
	        principals.add(principal);
	        Subject userSubject = new Subject(false,principals, pubCredentals, privCredentials); 
	        req.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
	        
	        edu.internet2.middleware.shibboleth.idp.session.Session shibbolethSession = 
	        		(edu.internet2.middleware.shibboleth.idp.session.Session) 
	        			req.getAttribute(
	        					edu.internet2.middleware.shibboleth.idp.session.Session.HTTP_SESSION_BINDING_ATTRIBUTE);
	        if (shibbolethSession != null)
	        {
	        	shibbolethSession.setSubject(userSubject);
	        	shibbolethSession.getAuthenticationMethods().clear();
	        }
	        
			Saml2LoginContext saml2LoginContext = (Saml2LoginContext)HttpServletHelper.getLoginContext(req);
			if (saml2LoginContext != null)
				saml2LoginContext.setAuthenticationMethodInformation(null); 
			
			LogRecorder.getInstance().addSuccessLogEntry(user, actualType, entityId, req.getRemoteAddr(), req.getSession());
	        			
	        if (returnPath == null) 
	        {
	            AuthenticationEngine.returnToAuthenticationEngine(req, resp);
	        }
	        else
	        {
	            resp.sendRedirect(returnPath);
	        }
        } 
        else if ("openid".equals(session.getAttribute("soffid-session-type")))
        {
        	AuthorizationResponse.generateResponse(ctx, req, resp);
        }
        else
        {
	        String returnPath = (String) session.getAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
	        if (returnPath != null) 
	        {
	            resp.sendRedirect(returnPath);
	        }
        	
        }
    }


    public boolean hasKerberosCookie (HttpServletRequest req) throws IOException
    {
        HttpSession session = req.getSession();
        IdpConfig config;
		try {
			config = IdpConfig.getConfig();
	        
	        String relyingParty = (String) session.
	                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
	        
	        if (relyingParty == null)
	        	return false;
	
	    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
	        if (ip == null)
	        	return false;
	        
	        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0)
	        {
	        	for (Cookie c: req.getCookies())
	        	{
	        		if (c.getName().equals(ip.getSsoCookieName()+"_krb") && c.getValue().equals("true"))
	        		{
	        			return true;
	        		}
	        	}
	        }

	        return false;
		} catch (Exception e) {
			return false;
		}
    }

	public void notifyLogout(edu.internet2.middleware.shibboleth.idp.session.Session indexedSession) throws NumberFormatException, InternalErrorException, IOException {
		Subject s = indexedSession.getSubject();
		if (s != null)
		{
			for ( SessionPrincipal sp: s.getPrincipals(SessionPrincipal.class))
			{
		        if (sp.getSessionString() != null)
		        {
			        String[] split = sp.getSessionString().split("\\|");
					if (split.length > 2)
					{
						String sessionid = split[0];
						String sessionKey = split[1];
						SessionService ss = new RemoteServiceLocator().getSessionService();
						Session soffidSession = ss
								.getSession(Long.decode(sessionid), sessionKey);
						if (ss != null)
							ss.destroySession(soffidSession);
					}
		        }
			}
		}
	}
	
	public String toSamlAuthenticationMethod (String method)
	{
		if (method == null)
			return null;
		if (method.equals("P"))
			return AuthnContext.PPT_AUTHN_CTX;
		else if (method.equals("PO"))
			return AuthnContext.MTFC_AUTHN_CTX;
		else if (method.equals("PC"))
			return AuthnContext.X509_AUTHN_CTX;
		else if (method.equals("E"))
			return AuthnContext.PREVIOUS_SESSION_AUTHN_CTX;
		else if (method.equals("EO"))
			return AuthnContext.MTFC_AUTHN_CTX;
		else if (method.equals("EC"))
			return AuthnContext.X509_AUTHN_CTX;
		else if (method.equals("K"))
			return AuthnContext.KERBEROS_AUTHN_CTX;
		else if (method.equals("KO"))
			return AuthnContext.MTFC_AUTHN_CTX;
		else if (method.equals("KC"))
			return AuthnContext.X509_AUTHN_CTX;
		else if (method.equals("O"))
			return AuthnContext.MTFC_AUTHN_CTX;
		else if (method.equals("OC"))
			return AuthnContext.X509_AUTHN_CTX;
		else if (method.equals("C"))
			return AuthnContext.X509_AUTHN_CTX;
		else
			return null;
	}

	public static String toSoffidAuthenticationMethod (String method)
	{
		if (method == null)
			return null;
		if (method.equals(AuthnContext.PPT_AUTHN_CTX))
			return "P";
		else if (method.equals(AuthnContext.KERBEROS_AUTHN_CTX))
			return "K";
		else if (method.equals(AuthnContext.MTFC_AUTHN_CTX))
			return "KO";
		else if (method.equals(AuthnContext.PASSWORD_AUTHN_CTX))
			return "P";
		else if (method.equals(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX))
			return "E";
		else if (method.equals(AuthnContext.SMARTCARD_AUTHN_CTX))
			return "C";
		else if (method.equals(AuthnContext.SMARTCARD_PKI_AUTHN_CTX))
			return "C";
		else if (method.equals(AuthnContext.SOFTWARE_PKI_AUTHN_CTX))
			return "P";
		else if (method.equals(AuthnContext.X509_AUTHN_CTX))
			return "C";
		else
			return null;
	}
}
