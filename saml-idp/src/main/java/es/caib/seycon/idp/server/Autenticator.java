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
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpRequest;
import org.jfree.util.Log;
import org.opensaml.saml2.core.AuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
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
import es.caib.seycon.idp.cas.LoginResponse;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.AuthorizationResponse;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.session.SessionCallbackServlet;
import es.caib.seycon.idp.session.SessionListener;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.shibext.SessionPrincipal;
import es.caib.seycon.idp.shibext.UidEvaluator;
import es.caib.seycon.idp.ui.ConsentFormServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.comu.TipusSessio;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.util.Base64;

public class Autenticator {
    private static final Logger LOG = LoggerFactory.getLogger(Autenticator.class);
    static Hashtable<String, Long> lastLogout = new Hashtable<>();
    
    public String generateSession (HttpServletRequest req, HttpServletResponse resp, String principal, String type, boolean externalAuth, String sessionId, String hostId) throws Exception
    {
        HttpSession session = req.getSession();
        ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        
        IdpConfig config = IdpConfig.getConfig();
        
        User user = server.getUserInfo(principal, config.getSystem().getName());
        
        server.updateExpiredPasswords(user, externalAuth);
        
        String url = "https://" + config.getHostName()+":"+config.getStandardPort()+ SessionCallbackServlet.URI;
        
		Session sessio = getSession(req, true);
		if (sessio == null) {
			sessio = new RemoteServiceLocator().getSessionService().registerWebSession(
        		user.getUserName(), config.getHostName(),
        		hostId == null ? LanguageFilter.getRemoteIp(): hostId,
        		url, type);
		}
		req.getSession().setAttribute("$$soffid_session$$", sessio);

        SessionListener.registerSession(session, sessio);
        
        FederationMemberSession fms = new FederationMemberSession();
        fms.setFederationMember(getRelyingParty(req));
        if (fms.getFederationMember() != null) {
	        fms.setSessionId(sessio.getId());
	        fms.setUserName( new UidEvaluator().evaluateUid(server, fms.getFederationMember(), principal, user));
	        fms.setSessionHash(sessionId);
        	if (sessionId == null)
        		req.getSession().setAttribute("$$soffid_incomplete_fms$$", fms);
        	else
        		config.getFederationService().createFederatioMemberSession(fms);
        }
        
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(SeyconKeyStore.getKeyStoreFile()),
        		SeyconKeyStore.getKeyStorePassword().getPassword().toCharArray());

        StringBuffer certBuffer = new StringBuffer();
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
        	String alias = e.nextElement();
        	Certificate cert = ks.getCertificate(alias);
        	if (certBuffer.length() > 0)
        		certBuffer
        			.append("-----END CERTIFICATE-----\n")
        			.append("-----BEGIN CERTIFICATE-----\n");
        	certBuffer.append(Base64.encodeBytes(cert.getEncoded()));
        }
        String certString = certBuffer.toString();
        
        Config serverConfig = Config.getConfig();

        StringBuffer buffer = new StringBuffer ();
        buffer.append (sessio.getId()).append("|").append(sessio.getKey()).
        	append("|").
        	append (certString).append("|").
        	append(serverConfig.getServerList());
        
        setCookie2 (req, resp, sessio, user, principal, type, externalAuth);
        return buffer.toString();
    }
    
    public boolean validateCookie (ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, String hostId) 
    		throws Exception
    {
        HttpSession session = req.getSession();
        IdpConfig config = IdpConfig.getConfig();
        
        String relyingParty = getRelyingParty(req);
        
        FederationMember ip = config.getFederationMember();
        if (relyingParty != null) {
	    	ip = config.findIdentityProviderForRelyingParty(relyingParty);
	        if (ip == null){
	        	LOG.info("Cannot find federation member "+relyingParty+" when loading cookie");
				return false;
	        }
		}
    	
        TokenInfo ti = (TokenInfo) req.getAttribute("$$internaltoken$$");
        if (ti != null && checkToken(ctx, req, resp, config, ti)) {
        	if (isValidSession(ti.getUser(), ti.getCreated()))
        		return true;
        }
        
        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0 && req.getCookies() != null)
        {
        	for (Cookie c: req.getCookies())
        	{
        		if (c.getName().equals(ip.getSsoCookieName()))
        		{
    				if (checkExternalCookie(ctx, req, resp, config, c, ip, hostId) || 
    						checkOwnCookie(ctx, req, resp, config, c, ip, hostId))
    					return true;
        		}
        	}
        }
        return false;
    }

	private boolean checkToken(ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, IdpConfig config,
			TokenInfo ti) throws Exception {
		if (ti == null)
			return false;
		String user = ti.getUser();
		if (user == null)
			return false;
		autenticate2(user, ctx, req, resp, ti.getAuthenticationMethod(), true, null);
		return true;
	}

	private boolean checkExternalCookie(ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, IdpConfig config, Cookie c, FederationMember ip, String hostId) 
			throws Exception {
		String value = c.getValue();
		// User remote version to avoid class cast exception error
		FederationService fs = (FederationService) new RemoteServiceLocator().getRemoteService(FederationService.REMOTE_PATH);
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
//					LOG.info("Session cookie is valid, but requested user does not match");
		            HttpSession session = req.getSession();
		            session.removeAttribute(SessionConstants.SEU_USER);
		            return false;
		        }
		        else {
					if (Boolean.TRUE.equals(ip.getAlwaysAskForCredentials()))
					{
				        String entityId = (String) req.getSession()
				        		.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
						AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
						if (authCtx == null)
						{
							authCtx = new AuthenticationContext();
							authCtx.setPublicId(entityId);
							authCtx.initialize( req );
						}
						authCtx.setFirstFactor(null);
						authCtx.setSecondFactor(null);
						authCtx.setStep(0);
						authCtx.setUser(user);
						authCtx.store(req);
						return false;
					} else {
						autenticate2(user, ctx, req, resp, "E", true, hostId);
						return true;
					}
		        }
			}
		}
		return check.isValid();
	}

	private boolean checkOwnCookie(ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, IdpConfig config, Cookie c, FederationMember ip, String hostId) throws Exception {
		Session session = getSession(req, false);
		if (session != null) {
			try {
				ServerService svc = new RemoteServiceLocator().getServerService();
				User u = svc.getUserInfo(session.getUserName(), null);
				if (u != null && u.getActive().booleanValue())
				{
					for (UserAccount account: svc.getUserAccounts(u.getId(), config.getSystem().getName()))
					{
						if (Boolean.TRUE.equals(ip.getAlwaysAskForCredentials()))
						{
					        String entityId = (String) req.getSession()
					        		.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
							AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
							if (authCtx == null)
							{
								authCtx = new AuthenticationContext();
								authCtx.setPublicId(entityId);
								authCtx.initialize( req );
							}
							authCtx.setFirstFactor(null);
							authCtx.setSecondFactor(null);
							authCtx.setStep(0);
							authCtx.setUser(account.getName());
							authCtx.store(req);
							return false;
						}
						else
						{
					        req.getSession().setAttribute("$$soffid_session$$", session);
							autenticate2(account.getName(), ctx, req, resp,  
									session.getAuthenticationMethod() == null ? "E" : session.getAuthenticationMethod(), 
									true, hostId);
			        		return true;
						}
					}
				}
			} catch (UnknownUserException e) {
				e.printStackTrace();
			}
		}
		return false;
	}
    

    private void setCookie2(HttpServletRequest req, HttpServletResponse resp,
			Session sessio, User user, String principal, String type, boolean externalAuth) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
        HttpSession session = req.getSession();
        IdpConfig config = IdpConfig.getConfig();
        
        String relyingParty = (String) session.
                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        
        if (relyingParty == null) // Can happen in username & password openid authentication
        	return;

    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
        if (ip == null)
        	throw new es.caib.seycon.ng.exception.InternalErrorException(String.format("Internal error. Cannot guess virtual identity provider for %s", relyingParty));

        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0)
        {
        	byte digest[] = MessageDigest.getInstance("SHA-256").digest(sessio.getKey().getBytes("UTF-8"));
        	String digestString = Base64.encodeBytes(digest);
        	String value = user.getId().toString()+"_"+digestString;
        	Cookie cookie = new Cookie(ip.getSsoCookieName(), value);
       		cookie.setMaxAge ( -1 );
        	cookie.setSecure(true);
        	cookie.setHttpOnly(true);
        	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
        		cookie.setDomain(ip.getSsoCookieDomain());
        	resp.addCookie(cookie);
        	if (type != null && type.contains("K"))
        	{
        		Cookie cookie2 = new Cookie (ip.getSsoCookieName()+"_krb", "true");
        		cookie2.setMaxAge(60 * 60 * 24 * 3 ); // 3 monthis to remember kerberos usage
            	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
            		cookie2.setDomain(ip.getSsoCookieDomain());
            	resp.addCookie(cookie2);
        	}

        	if (! externalAuth && ! type.startsWith("C") && ! type.startsWith("E") &&
        			Boolean.TRUE.equals(ip.getStoreUser())) {
	        	Cookie cookieUser = new Cookie(ip.getSsoCookieName()+"_user", principal);
	       		cookieUser.setMaxAge( 30 * 24 * 60 * 60_000  ); // Remember for one month
	        	cookieUser.setSecure(true);
	        	cookieUser.setHttpOnly(true);
	        	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
	        		cookieUser.setDomain(ip.getSsoCookieDomain());
	        	resp.addCookie(cookieUser);
        	} else {
	        	Cookie cookieUser = new Cookie(ip.getSsoCookieName()+"_user", "");
	       		cookieUser.setMaxAge( 0 );
	        	cookieUser.setSecure(true);
	        	cookieUser.setHttpOnly(true);
	        	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
	        		cookieUser.setDomain(ip.getSsoCookieDomain());
	        	resp.addCookie(cookieUser);
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
    
	public void autenticate2 (String user, ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, String type, boolean externalAuth, String hostId) throws Exception {
    	autenticate2(user, ctx, req, resp, type, type, externalAuth, hostId);
    }
    
    public void autenticate2 (String user, ServletContext ctx, HttpServletRequest req, HttpServletResponse resp, String type, String actualType, boolean externalAuth,
    		String hostId) throws Exception {

        LOG.info("Remote user identified as "+user+". returning control back to authentication engine "); //$NON-NLS-1$ //$NON-NLS-2$

        HttpSession session = req.getSession();
        
        String entityId = (String) session
        		.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        session.setAttribute(SessionConstants.SEU_USER, user);
        session.setAttribute(SessionConstants.AUTHENTICATION_USED, type);
		AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
		if (authCtx == null)
		{
			authCtx = new AuthenticationContext();
			authCtx.setPublicId(entityId);
			authCtx.initialize( req );
		}
		authCtx.setFirstFactor(type.substring(0, 1));
		authCtx.setSecondFactor(type.substring(1));
		authCtx.setStep(2);
		authCtx.setUser(user);
		authCtx.store(req);

		// Search for consent
		if (authCtx.getPublicId() != null && !authCtx.getPublicId().trim().isEmpty()) {
			if ( ! authCtx.hasConsent()) {
				resp.sendRedirect(ConsentFormServlet.URI);
				return;
			}
		}
		

		edu.internet2.middleware.shibboleth.idp.session.Session shibbolethSession = 
				(edu.internet2.middleware.shibboleth.idp.session.Session) 
				req.getAttribute(
						edu.internet2.middleware.shibboleth.idp.session.Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        LOG.info("Session type " + session.getAttribute("soffid-session-type")); //$NON-NLS-1$ //$NON-NLS-2$
        if ("saml".equals(session.getAttribute("soffid-session-type")))
        {
        	final String soffidSession = generateSession(req, resp, user, type, externalAuth, null, hostId);
        	LogRecorder.getInstance().addSuccessLogEntry("SAML", user, actualType, entityId, req.getRemoteAddr(), req.getSession(), shibbolethSession, null);
	        String returnPath = (String) session.getAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
	
			Principal principal = new SessionPrincipal(user, soffidSession);
	        
	        req.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
	        req.setAttribute(LoginHandler.PRINCIPAL_NAME_KEY, user);
	        Set<Principal> principals = new HashSet<Principal> ();
	        Set<?> pubCredentals = new HashSet<Object>();
	        Set<?> privCredentials = new HashSet<Object>();
	        principals.add(principal);
	        Subject userSubject = new Subject(false,principals, pubCredentals, privCredentials); 
	        req.setAttribute(LoginHandler.SUBJECT_KEY, userSubject);
	        
	        if (shibbolethSession != null)
	        {
	        	shibbolethSession.setSubject(userSubject);
	        	shibbolethSession.getAuthenticationMethods().clear();
	        }
	        
			Saml2LoginContext saml2LoginContext = (Saml2LoginContext)HttpServletHelper.getLoginContext(req);
			if (saml2LoginContext != null) {
				List<String> set = saml2LoginContext.getRequestedAuthenticationMethods();
				String actualLogin = toSamlAuthenticationMethod(type);
				if (set.isEmpty() || set.contains(actualLogin))
					req.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, actualLogin);
				else
					req.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, set.iterator().next());
			}
			
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
        	LOG.info("Generating openid response");
        	String sessionHash = generateRandomSessionId();
        	final String soffidSession = generateSession(req, resp, user, type, externalAuth, sessionHash, hostId);
        	AuthorizationResponse.generateResponse(ctx, req, resp, type, sessionHash);
        }
        else if ("cas".equals(session.getAttribute("soffid-session-type")))
        {
        	LOG.info("Generating openid response");
        	String sessionHash = generateRandomSessionId();
        	final String soffidSession = generateSession(req, resp, user, type, externalAuth, sessionHash, hostId);
        	LoginResponse.generateResponse(ctx, req, resp, type, sessionHash);
        }
        else
        {
        	generateSession(req, resp, user, type, externalAuth, generateRandomSessionId(), hostId);
	        String returnPath = (String) session.getAttribute(SessionConstants.AUTHENTICATION_REDIRECT);
	        if (returnPath != null) 
	        {
	            resp.sendRedirect(returnPath);
	        }
        	
        }
    }

    static SecureRandom secureRandom = new SecureRandom();
    public String generateRandomSessionId() {
    	byte b[] = new byte[24];
    	secureRandom.nextBytes(b);
		return Base64.encodeBytes(b, Base64.DONT_BREAK_LINES);
	}

	public String getRelyingParty (HttpServletRequest request) {
    	HttpSession session = request.getSession();
        if ("saml".equals(session.getAttribute("soffid-session-type")))
        {
        	return (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        } 
        else if ("openid".equals(session.getAttribute("soffid-session-type")))
        {
    		OpenIdRequest r = (OpenIdRequest) session.getAttribute(SessionConstants.OPENID_REQUEST);
    		if (r != null)
    			return r.getFederationMember().getPublicId();
        }
        else if ("cas".equals(session.getAttribute("soffid-session-type")))
        {
    		OpenIdRequest r = (OpenIdRequest) session.getAttribute(SessionConstants.OPENID_REQUEST);
    		if (r != null)
    			return r.getFederationMember().getPublicId();
        }
        return null;
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

    public boolean isValidSession(String name, long sessionTimestamp) {
    	Long l = lastLogout.get(name);
    	if (l == null || l.longValue() < sessionTimestamp)
    		return true;
    	else
    		return false;
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
		else if (method.equals("Z"))
			return AuthnContext.MOFC_AUTHN_CTX;
		else
			return null;
	}

	public static Collection<String> toSoffidAuthenticationMethod (String method)
	{
		String values[] = null;
		if (method == null)
			return null;
		if (method.equals(AuthnContext.PPT_AUTHN_CTX))
			values = new String[] { "P", "Z", "K", "C", "O", "E", "I","M","S", "PO", "PC", "KO", "KC", "KZ", "PI", "PM", "PS", "Z", "PZ" };
		else if (method.equals(AuthnContext.KERBEROS_AUTHN_CTX))
			values = new String[] { "K", "KO", "KI", "KM", "KS", "KC", "KZ", "C" };
		else if (method.equals(AuthnContext.MTFC_AUTHN_CTX))
			values = new String[] { "PO", "KO", "C", "EO", "PI", "PM", "PS", "PZ", "KZ"};
		else if (method.equals(AuthnContext.PASSWORD_AUTHN_CTX))
			values = new String[] { "P", "K", "C", "O", "E", "I","M", "S", "Z", "PO", "PC", "KO", "KC", "KZ", "PI", "PM", "PS", "PZ" };
		else if (method.equals(AuthnContext.PREVIOUS_SESSION_AUTHN_CTX))
			values = new String[] { "P", "K", "C", "O", "E", "I", "M", "S", "Z", "PO", "PC", "KO", "KC", "KZ",
									"PI", "PM", "PS", "PZ"};
		else if (method.equals(AuthnContext.SMARTCARD_AUTHN_CTX))
			values = new String[] { "C", "CO", "CI", "CM", "CS" };
		else if (method.equals(AuthnContext.SMARTCARD_PKI_AUTHN_CTX))
			values = new String[] { "C", "CO", "CI", "CM", "CS" };
		else if (method.equals(AuthnContext.SOFTWARE_PKI_AUTHN_CTX))
			values = new String[] { "C", "CO", "CI", "CM", "CS" };
		else if (method.equals(AuthnContext.X509_AUTHN_CTX))
			values = new String[] { "C", "CO", "CI", "CM", "CS" };
		else
			return null;
		
		if (values == null)
			return null;
		else
			return Arrays.asList(values);
	}

	public Session generateImpersonatedSession(HttpSession httpSession, String userName, String authenticationType, boolean externalAuth) throws InternalErrorException, UnknownUserException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
        ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        
        IdpConfig config = IdpConfig.getConfig();
        
        User user = server.getUserInfo(userName, null);
        
        server.updateExpiredPasswords(user, externalAuth);
        
        String url = "https://" + config.getHostName()+":"+config.getStandardPort()+ SessionCallbackServlet.URI;
        
        com.soffid.iam.api.Session sessio = new RemoteServiceLocator().getSessionService().registerWebSession(
        		user.getUserName(), config.getHostName(),
        		LanguageFilter.getRemoteIp(),
        		url, authenticationType);

        SessionListener.registerSession(httpSession, sessio);
        
        return sessio;
	}

	public Cookie generateSessionCookie(TokenInfo token, Session session) 
			throws InternalErrorException, UnknownUserException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException 
	{
        IdpConfig config = IdpConfig.getConfig();

        FederationMember federationMember = token.getRequest().getFederationMember();
    	FederationMember ip = config.findIdentityProviderForRelyingParty(federationMember.getPublicId());
        if (ip == null)
        	throw new es.caib.seycon.ng.exception.InternalErrorException(String.format("Internal error. Cannot guess virtual identity provider for %s", federationMember.getPublicId()));

        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0)
        {
        	byte digest[] = MessageDigest.getInstance("SHA-256").digest(session.getKey().getBytes("UTF-8"));
        	String digestString = Base64.encodeBytes(digest);
        	User user = new RemoteServiceLocator().getServerService().getUserInfo(session.getUserName(), null);
        	String value = user.getId().toString()+"_"+digestString;
        	Cookie cookie = new Cookie(ip.getSsoCookieName(), value);
       		cookie.setMaxAge ( -1 );
        	cookie.setHttpOnly(true);
        	cookie.setSecure(true);
        	if (ip.getSsoCookieDomain() != null && ip.getSsoCookieDomain().length() > 0)
        		cookie.setDomain(ip.getSsoCookieDomain());
        	return cookie;
        } else {
        	return null;
        }
	}
	
	public Session getSession (HttpServletRequest request, boolean useCache) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
        HttpSession s = request.getSession();
        Session session = (Session) s.getAttribute("$$soffid_session$$");
        if (useCache && session != null)
        	return session;
        
        IdpConfig config = IdpConfig.getConfig();
        FederationMember ip = config.getFederationMember();
        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0 && request.getCookies() != null)
        {
        	for (Cookie c: request.getCookies())
        	{
        		if (c.getName().equals(ip.getSsoCookieName()))
        		{
        			String value = c.getValue();
        			if (! value.contains(":")) {
        				return fetchSessionFromIdpCookie(value);
        			}
        		}
        	}
        }
        return null;
	}

	private Session fetchSessionFromIdpCookie(String value) throws NoSuchAlgorithmException, UnsupportedEncodingException, InternalErrorException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		int separator = value.indexOf('_');
		if (separator > 0)
		{
			FederationMember ip = IdpConfig.getConfig().getFederationMember();
			
			String hash = value.substring(separator+1);
			Long id = Long.decode(value.substring(0, separator));
			for (Session sessio: new RemoteServiceLocator().getSessionService().getActiveSessions(id))
			{
				if (sessio != null && sessio.getType() == TipusSessio.WSSO) {
					byte digest[] = MessageDigest.getInstance("SHA-256").digest(sessio.getKey().getBytes("UTF-8"));
					String digestString = Base64.encodeBytes(digest);
					if (digestString.equals(hash) &&
						(ip.getMaxSessionDuration() == null || 
						sessio.getStartDate().getTime().getTime() + ip.getMaxSessionDuration().longValue() * 1000 > System.currentTimeMillis()))
					{
						return sessio;
					}
				}					
			}
		}
		return null;
	}
	
	public void clearCookies(HttpServletRequest req, HttpServletResponse resp) throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
		IdpConfig config = IdpConfig.getConfig();
        String relyingParty = getRelyingParty(req);
        
        FederationMember ip = config.getFederationMember();
        if (relyingParty != null) {
	    	FederationMember ip2 = config.findIdentityProviderForRelyingParty(relyingParty);
	        if (ip2 != null) {
	        	ip = ip2;
	        }
		}
    	
        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0 && req.getCookies() != null)
        {
        	Cookie c = new Cookie(ip.getSsoCookieName(), "-");
        	c.setMaxAge(0);
        	resp.addCookie(c);
        }
	}

}
