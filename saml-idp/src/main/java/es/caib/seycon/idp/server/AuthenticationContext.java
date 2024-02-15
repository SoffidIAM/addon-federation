package es.caib.seycon.idp.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.api.adaptive.ActualAdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.idp.radius.attribute.RadiusAttribute;
import com.soffid.iam.addons.federation.idp.radius.packet.AccessRequest;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.addons.federation.service.impl.IssueHelper;
import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.User;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.CertificateValidator;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.util.Base64;
import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgent.ImmutableUserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;

public class AuthenticationContext {
	String publicId;
	Set<String> requestedAuthenticationMethod;
	int step;
	String firstFactor;
	String secondFactor;
	Set<String> nextFactor;
	private Date certificateWarning;
	private boolean certificateWarningDone;
	private String user;
	private Set<String> allowedAuthenticationMethods;
	private String remoteIp;
	private String hostId;
	private User currentUser;
	private Account currentAccount;
	private UserCredential newCredential;
	private boolean deviceCertificate = false;
	long timestamp = 0;
	private Challenge challenge;
	private Collection<UserCredentialChallenge> pushChallenge;
	
	static Log log = LogFactory.getLog(AuthenticationContext.class);

	private boolean alwaysAskForCredentials;
	private String radiusState;
	private long created;
	boolean underAttack = false;
	private String device; 
	private String os;
	private String browser;
	private String cpu;
	private RecoverPasswordChallenge recoverChallenge;

	public static AuthenticationContext fromRequest (HttpServletRequest r)
	{
		if (r == null)
			return null;
		AuthenticationContext auth = (AuthenticationContext) r.getSession().getAttribute("Soffid-Authentication-Context");
		if (auth == null)
			return null;
		if (!auth.isFinished())
			return auth;
		if (new Autenticator().isValidSession(auth.getUser(), auth.getTimestamp()))
			return auth;
		else
			return null;
	}
	

	public void store (HttpServletRequest r)
	{
		if (r != null)
			r.getSession().setAttribute("Soffid-Authentication-Context", this);
	}
	
	public AuthenticationContext ()
	{
		created = System.currentTimeMillis();
	}
	
	
	public String getHostIdCookieName () throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException 
	{
		IdpConfig config = IdpConfig.getConfig();
    	FederationMember fm = config.findIdentityProviderForRelyingParty(publicId);
    	if (fm.getSsoCookieName() != null && ! fm.getSsoCookieName().trim().isEmpty())
    		return fm.getSsoCookieName()+"_host_id";
    	else
    		return "hostid";
		
	}
	
	public String getUserCookieName () throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException 
	{
		IdpConfig config = IdpConfig.getConfig();
    	FederationMember fm = config.findIdentityProviderForRelyingParty(publicId);
    	if (fm.getSsoCookieName() != null && ! fm.getSsoCookieName().trim().isEmpty())
    		return fm.getSsoCookieName()+"_user";
    	else
    		return null;
		
	}

	public void initialize (HttpServletRequest request) 
		throws Exception
	{
		IdpConfig config = IdpConfig.getConfig();
    	remoteIp = getClientRequest(request);
    	parseUserAgent(request);
    	hostId = null;
    	String cookieName = getHostIdCookieName();
    	String userCookie = getUserCookieName();
    	
    	FederationMember idp = config.getFederationMember();
        String relyingParty = (String) request.getSession().getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        
        if (relyingParty != null) {
        	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
        	if (ip != null) idp = ip;
        }

    	currentUser = null;
    	if (cookieName != null && request != null && request.getCookies() != null)
    	{
			for (Cookie cookie: request.getCookies()) {
				if (cookie.getName().equals(userCookie) && Boolean.TRUE.equals(idp.getStoreUser())) {
					String u = cookie.getValue();
					user = u;
				}
    			if (cookie.getName().equals(cookieName))
    				hostId = cookie.getValue();
			}
    	}
    	
    	fetchHostIdFromCert(request);
    	
    	currentUser = null;

    	try {
    		if (user != null)
    			getUserData(user);
    	} catch (Exception e) {
    		// User no longer exists
    	}
    	updateAllowedAuthenticationMethods();
//        if (allowedAuthenticationMethods.isEmpty())
//        	throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        onInitialStep();
	}


	private void fetchHostIdFromCert(HttpServletRequest request) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException, UnknownUserException {
		CertificateValidator v = new CertificateValidator();
		X509Certificate[] certs = null;
		try {
			certs = v.getCerts(request);
		} catch (InternalErrorException e) {
			// Ignore
		}
		if (certs != null) {
			Host host = v.validateHost(certs, hostId);
			if (host != null) {
				Date warning = IdpConfig.getConfig().getFederationService()
						.getCertificateExpirationWarning(Arrays.asList( certs ));
				if (warning != null) 
					this.certificateWarning = warning;
				deviceCertificate = true;
				if (hostId == null) {
					hostId = host.getSerialNumber();
				}
				else if (!hostId.equals(host.getSerialNumber())) {
					Host host2 = new RemoteServiceLocator()
							.getUserBehaviorService()
							.findHostBySerialNumber(hostId);
					if (host2 != null) {
						try {
							IssueHelper.deviceCertificateBorrowed(host, host2);
						} catch (Throwable th) {
							// Ignore
						}
					}
				}
			}
		}
	}


	public void onInitialStep() {
		nextFactor = new HashSet<String>();
        firstFactor = null;
        secondFactor = null;
        step = 0;
        timestamp = System.currentTimeMillis();
        
        if (nextFactor.isEmpty())
        {
            for ( String allowedMethod: allowedAuthenticationMethods)
            {
            	if (!allowedMethod.isEmpty())
            		nextFactor.add( allowedMethod.substring(0,1));
            }
        }
	}
	
	public static String getClientRequest (HttpServletRequest req)
	{
		String ip = req.getRemoteAddr();
		return ip;
	}
	
	static UserAgentAnalyzer uaa = UserAgentAnalyzer
			.newBuilder()
			.withField(UserAgent.DEVICE_NAME)
			.withField(UserAgent.OPERATING_SYSTEM_NAME)
			.withField(UserAgent.DEVICE_CPU)
			.withField(UserAgent.AGENT_NAME_VERSION)
			.hideMatcherLoadStats()
			.withCache(500)
			.build();

	public void parseUserAgent(HttpServletRequest req) {
		
		Map<String,String> headers = new HashMap<>();
		for (Enumeration<String> e = req.getHeaderNames(); e.hasMoreElements(); ) {
			String key = e.nextElement();
			headers.put(key, req.getHeader(key));
		}
		synchronized (uaa) {
			ImmutableUserAgent p = uaa.parse(headers);
			os = p.get(UserAgent.OPERATING_SYSTEM_NAME).getValue();
			cpu = p.get(UserAgent.DEVICE_CPU).getValue();
			browser = p.get(UserAgent.AGENT_NAME_VERSION).getValue();
			device = p.get(UserAgent.DEVICE_NAME).getValue();
		}
	}

	public boolean isPreviousAuthenticationMethodAllowed (HttpServletRequest request) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
	{
		HttpSession session = request.getSession(true);
        if (step != 2)
        	return false;

        String method = getUsedMethod();
        
        Set<String> previous = allowedAuthenticationMethods;
        updateAllowedAuthenticationMethods();
        HashSet<String> allowed = new HashSet<>(allowedAuthenticationMethods);
        if (requestedAuthenticationMethod != null && ! requestedAuthenticationMethod.isEmpty())
        	allowed.retainAll(requestedAuthenticationMethod);
        
        if (allowed.isEmpty())
        	throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        
        if (allowed.contains(method))
        {
        	firstFactor = method.substring(0, 1);
        	secondFactor = method.length() > 1 ? method.substring(1,2) : null;
        	nextFactor = null;
        	step = 2;
        	return true;
        }
        
        nextFactor = new HashSet<String>();
        firstFactor = null;
        secondFactor = null;
        step = 0;
        for ( String allowedMethod: allowed)
        {
        	if ( allowedMethod.startsWith(method))
        	{
        		firstFactor = method;
        		step = 1;
        		nextFactor.add( allowedMethod.substring(1));
        	}
        }
        
        if (nextFactor.isEmpty())
        {
            for ( String allowedMethod: allowed)
            {
           		nextFactor.add( allowedMethod.substring(0,1));
            }
        }
        
        
        return false;
	}
	
	
	
	public void updateAllowedAuthenticationMethods() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
		IdpConfig config = IdpConfig.getConfig();
    	FederationMember fm = config.findIdentityProviderForRelyingParty(publicId);
    		
    	ActualAdaptiveEnvironment env = new ActualAdaptiveEnvironment(currentUser, remoteIp, hostId, deviceCertificate);
    	Integer f = failuresByIp.get(remoteIp);
    	env.setFailuresForSameIp(f == null ? 0: f.intValue());
    	env.setFailuresRatio(worstAthenticationRatio());
    	env.setHostId(hostId);
    	env.setIdentityProvider(fm.getPublicId());
    	env.setServiceProvider(publicId);
    	env.setSourceIp(remoteIp);
    	env.setUser(currentUser);
		AuthenticationMethod m = new RemoteServiceLocator().getUserBehaviorService().getAuthenticationMethod(fm, env );
		alwaysAskForCredentials = Boolean.TRUE.equals( m.getAlwaysAskForCredentials() );

		HashSet<String> methods = new HashSet<String>(); 
		for ( String s: m.getAuthenticationMethods().split(" "))
		{
			if (!s.trim().isEmpty())
				methods.add(s);
		}
		this.allowedAuthenticationMethods = methods;
	}


	public String getPublicId() {
		return publicId;
	}

	public void setPublicId(String publicId) {
		this.publicId = publicId;
	}

	public Set<String> getRequestedAuthenticationMethod() {
		return requestedAuthenticationMethod;
	}

	public void setRequestedAuthenticationMethod(Set<String> requestedAuthenticationMethod) {
		this.requestedAuthenticationMethod = requestedAuthenticationMethod;
	}

	public int getStep() {
		return step;
	}

	public void setStep(int step) {
		this.step = step;
	}

	public String getFirstFactor() {
		return firstFactor;
	}

	public void setFirstFactor(String firstFactor) {
		this.firstFactor = firstFactor;
	}

	public String getSecondFactor() {
		return secondFactor;
	}

	public void setSecondFactor(String secondFactor) {
		this.secondFactor = secondFactor;
	}

	public Set<String> getNextFactor() {
		return nextFactor;
	}

	public void setNextFactor(Set<String> nextFactor) {
		this.nextFactor = nextFactor;
	}


	public String getPreviousFactor() {
		if ( step == 1 )
			return firstFactor;
		if ( step == 2 )
			return secondFactor;
		
		return null;
	}


	public String getUsedMethod()
	{
		if (firstFactor == null) return null;
		else if (secondFactor == null) return firstFactor;
		else return firstFactor + secondFactor;
	}
	
	public boolean isFinished ()
	{
		return step == 2;
	}
	
	
	public void authenticated (String user, String method, HttpServletResponse resp) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
	{
		if ( step == 1 && method.equals(firstFactor))
			return;
		
		if (step == 2 && method.equals(secondFactor))
			return;

		if (step == 0 ) // Load user information and reevaluate authentication methods
		{
			getUserData(user);
		
			updateAllowedAuthenticationMethods();
			onInitialStep();
		} else if ( user != null && ! user.equals(currentAccount.getName())){
			throw new InternalErrorException( String.format("Cannot mix credentials of %s and %s", user, currentAccount.getName()));
		}
		
		if (nextFactor == null || ! nextFactor.contains(method))
			throw new InternalErrorException("Authentication method '"+method+"' not allowed. Expected one of '"+nextFactor+"'. Allowed methods: "+allowedAuthenticationMethods);

		if (step == 0) 
		{
			this.user = user;
			firstFactor = method;
		}
		else 
			secondFactor = method;
		
		String m = getUsedMethod();
		nextFactor.clear();
    	if ( allowedAuthenticationMethods.contains(m))
    	{
    		regesterLogonAudit(resp);
    		step = 2;
    		timestamp = System.currentTimeMillis();
    		registerNewCredential();
    		feedRatio(false);
    	}
    	else
    	{
    		for ( String allowedMethod: allowedAuthenticationMethods)
    		{
    			if ( allowedMethod.startsWith(method))
    			{
    				firstFactor = method;
    				step = 1;
    				nextFactor.add( allowedMethod.substring(1));
    			}
    		}
    	}
        
        if (step == 0)
        	throw new InternalErrorException ("Internal error. No authentication method is allowed");
	}


	protected void regesterLogonAudit(HttpServletResponse resp) throws IOException, InternalErrorException,
			UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException {
		if (currentUser != null)
		{
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			long f = ubh.getUserFailures(currentUser.getId());
			ubh.setUserFailures(currentUser.getId(), 0);
			if (hostId != null)
				updateHost(ubh);
			if (hostId == null && resp != null)
			{
				registerHost(ubh);
				Cookie c2 = new Cookie(getHostIdCookieName(), hostId);
				c2.setSecure(true);
				c2.setMaxAge(Integer.MAX_VALUE);
				c2.setHttpOnly(true);
				c2.setPath("/");
				resp.addCookie(c2);
			}
			if (hostId != null) {
				checkLockedHost(ubh);
			}
			ubh.registerLogon(currentUser.getId(), remoteIp, hostId);
			if (currentAccount != null) {
				currentAccount = new RemoteServiceLocator().getAccountService().findAccountById(currentAccount.getId());
				currentAccount.setLastLogin(Calendar.getInstance());
				try {
					new RemoteServiceLocator().getAccountService().updateAccount(currentAccount);
				} catch (AccountAlreadyExistsException e) {
				}
				Audit a = new Audit();
				a.setAccount(currentAccount.getName());
				a.setUser(currentUser.getUserName());
				a.setAction("S");
				a.setObject("LOGIN");
				a.setDatabase(currentAccount.getSystem());
				a.setCalendar(Calendar.getInstance());
				a.setSourceIp(remoteIp);
				a.setHost(hostId);
				new RemoteServiceLocator().getFederacioService().registerLoginAudit(a);
			}
		}
	}


	private void checkLockedHost(UserBehaviorService ubh) throws InternalErrorException {
		Host h = ubh.findHostBySerialNumber(hostId);
		if (h != null) {
			Boolean locked;
			try {
				locked = (Boolean) h.getClass().getMethod("getLocked").invoke(h);
				if (locked != null && locked.booleanValue()) {
					throw new InternalErrorException("Your device is locked");
				}
			} catch (Exception e) {
			}
		}
	}


	protected void registerHost(UserBehaviorService ubh) throws InternalErrorException {
		hostId = ubh.registerHost(remoteIp, device, browser, os, cpu);
	}

	protected void updateHost(UserBehaviorService ubh) throws InternalErrorException {
		ubh.updateHost(hostId, remoteIp, device, browser, os, cpu);
	}

	private void registerNewCredential() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		if (currentUser !=null && newCredential != null)
		{
			newCredential.setUserId(currentUser.getId());
			IdpConfig.getConfig().getUserCredentialService().create(newCredential);
		}
	}

	public void authenticationFailure (String u, String comments) throws IOException, InternalErrorException
	{
		getUserData(u);
		feedRatio(true);
		if (u != null && currentUser != null)
		{
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			long f = ubh.getUserFailures(currentUser.getId());
			ubh.setUserFailures(currentUser.getId(), f+1);
			Audit a = new Audit();
			a.setAccount(currentAccount.getName());
			a.setUser(currentUser.getUserName());
			a.setAction("P");
			a.setObject("LOGIN");
			a.setDatabase(currentAccount.getSystem());
			a.setCalendar(Calendar.getInstance());
			a.setComment(comments);
			a.setSourceIp(remoteIp);
			a.setHost(hostId);
			new RemoteServiceLocator().getFederacioService().registerLoginAudit(a);
		} else {
			Audit a = new Audit();
			a.setUser(u);
			a.setAction("U");
			a.setObject("LOGIN");
			a.setCalendar(Calendar.getInstance());
			a.setComment(comments);
			a.setSourceIp(remoteIp);
			a.setHost(hostId);
			new RemoteServiceLocator().getFederacioService().registerLoginAudit(a);
		}
		double ratio = worstAthenticationRatio();
		if (ratio > 0.8 && !underAttack)
			try {
				underAttack = true;
				CreateIssueHelper.globalFailedLogin(ratio);
			} catch (Error e) {
				// Older syncserver version
			}
		else if (ratio < 0.5)
			underAttack = false;
	}
	
	public boolean isLocked (String u) throws IOException, InternalErrorException
	{
    	IdpConfig cfg;
		try {
			cfg = IdpConfig.getConfig();
		} catch (Exception e) {
			throw new InternalErrorException("Error getting default dispatcher", e);
		}
	    String d = cfg.getSystem().getName();
	    Account account = new RemoteServiceLocator().getAccountService().findAccount(u, d);
		if (account != null)
		{
			if (account.isDisabled())
				return true;
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			return ubh.isLocked(currentAccount.getId());
		}
		return false;
	}

	private void getUserData(String userName) throws InternalErrorException, IOException {
    	IdpConfig cfg;
		try {
			cfg = IdpConfig.getConfig();
		} catch (Exception e) {
			throw new InternalErrorException("Error getting default dispatcher", e);
		}
	    String d = cfg.getSystem().getName();
	    currentAccount = new RemoteServiceLocator().getAccountService().findAccount(userName, d);

	    if (currentAccount == null || currentAccount.isDisabled()) {
	    	try {
	    		CreateIssueHelper.wrongUser(userName, hostId, remoteIp);
	    	} catch (Error e) {}
	    	throw new InternalErrorException("The account "+userName+" is disabled");
	    }
	    
	    if (currentAccount != null && currentAccount.getType() == AccountType.USER && currentAccount.getOwnerUsers() != null && currentAccount.getOwnerUsers().size() == 1)
	    	currentUser = new RemoteServiceLocator().getUserService().findUserByUserName(currentAccount.getOwnerUsers().iterator().next());
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public FederationMember getIdentityProvider() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		IdpConfig config = IdpConfig.getConfig();
    	return config.findIdentityProviderForRelyingParty(publicId);
	}

	public void setSamlRequestedAuthenticationMethod(Set<String> samlMethods) {
		if (samlMethods == null || samlMethods.isEmpty())
			requestedAuthenticationMethod = null;
		else {
			requestedAuthenticationMethod = new HashSet<String>();
			for (String method: samlMethods)
			{
				requestedAuthenticationMethod.addAll ( Autenticator.toSoffidAuthenticationMethod(method));
			}
		}
		
	}

	public Set<String> getAllowedAuthenticationMethods() {
		return allowedAuthenticationMethods;
	}

	public void setAllowedAuthenticationMethods(Set<String> allowedAuthenticationMethods) {
		this.allowedAuthenticationMethods = allowedAuthenticationMethods;
	}

	// failures ratio calculation
	static int successByMinute[]  = new int [60];
	static int failureByMinute[] = new int [60];
	static int lastAnnotation = 0;
	static HashMap<String,Integer>failuresByIp = new HashMap<String, Integer>();
	double worstAthenticationRatio () {
		int minute = (int) ((System.currentTimeMillis() / 60000L) % 60);
		int start = minute;
		int failures = 0;
		int total = 0;
		double worst = 0.0;
		do {
			failures += failureByMinute[minute];
			total += failureByMinute[minute] + successByMinute[minute];
			if (total > 10)
			{
				double ratio = failures / total;
				if (ratio > worst) worst = ratio;
			}
			minute = (minute + 1) % 60;
		} while (minute != start);
		return worst;
	}
	void feedRatio (boolean failure)
	{
		int minute = (int) ((System.currentTimeMillis() / 60000L) % 60);
		while (lastAnnotation != minute)
		{
			lastAnnotation = (lastAnnotation + 1) % 60;
			failureByMinute[lastAnnotation] = successByMinute[lastAnnotation] = 0;
		}
		if (failure)
		{
			failureByMinute[lastAnnotation] ++;
			Integer i = failuresByIp.get(remoteIp);
			if (i == null)
				failuresByIp.put(remoteIp, new Integer(1));
			else
				failuresByIp.put(remoteIp, new Integer (i.intValue()+1));
		} else {
			failuresByIp.remove(remoteIp);
			successByMinute[lastAnnotation] ++;
		}
	}

	public void setNewCredential(UserCredential credential) {
		newCredential = credential;
	}

	public void addConsent() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		String userName = currentUser.getUserName();
		IdpConfig.getConfig().getFederationService().addConsent(userName, publicId);
	}
	
	public boolean hasConsent() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		if (currentUser == null)
			getUserData(user);
		String userName = currentUser.getUserName();
		return IdpConfig.getConfig().getFederationService().hasConsent(userName, publicId);
	}

	public User getCurrentUser() {
		return currentUser;
	}


	public long getTimestamp() {
		return timestamp;
	}


	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}


	public String getHostId( HttpServletResponse resp) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		if (hostId == null) {
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			if (hostId == null)
			{
				registerHost(ubh);
				Cookie c2 = new Cookie(getHostIdCookieName(), hostId);
				c2.setSecure(true);
				c2.setMaxAge(Integer.MAX_VALUE);
				c2.setHttpOnly(true);
				c2.setPath("/");
				resp.addCookie(c2);
			}
			
		}
		return hostId;
	}


	public void setChallenge(Challenge ch) {
		this.challenge = ch;
	}


	public Challenge getChallenge() {
		return challenge;
  }
  
	public boolean isAlwaysAskForCredentials() {
		return alwaysAskForCredentials;
	}


	static Map<String, AuthenticationContext> auths = new Hashtable<>();
	static long lastPurge = 0;

	public static AuthenticationContext fromRequest(AccessRequest accessRequest, InetAddress sourceAddress, String publicId, boolean secure) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		expireOldContexts();
		
		if (accessRequest == null)
			return null;
		RadiusAttribute state = accessRequest.getAttribute(24); // State
		AuthenticationContext auth = null;
		if (state != null) {
			
		}
		if (state != null) {
			auth = auths.get(new String( state.getAttributeData(), "UTF-8"));
		}
		if (auth == null) {
			auth = new AuthenticationContext();
			byte[] random = new byte[24];
			new SecureRandom().nextBytes(random);
			String s = Base64.encodeBytes(random, Base64.DONT_BREAK_LINES);
			auth.radiusState = s;
			auth.initialize(accessRequest, sourceAddress, publicId, secure);
			auths.put(auth.getRadiusState(), auth);
		}
		return auth;
	}

	private void initialize(AccessRequest accessRequest, InetAddress sourceAddress, String publicId, boolean secure) throws InternalErrorException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		IdpConfig config = IdpConfig.getConfig();
    	remoteIp = accessRequest.getAttributeValue("Framed-IP-Address");
    	if (remoteIp == null)
    		remoteIp = sourceAddress.getHostAddress();
    	os = "Unknown";
    	browser = "Radius";
    	cpu = null;
    	deviceCertificate = secure;
    	
    	hostId = null;
    	currentUser = null;
    	this.publicId = publicId;
    	user = accessRequest.getUserName();
    	getUserData(accessRequest.getUserName());

    	updateAllowedAuthenticationMethods();
        if (requestedAuthenticationMethod != null)
        {
        	allowedAuthenticationMethods.retainAll(requestedAuthenticationMethod);
        	if (allowedAuthenticationMethods.isEmpty())
        		throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        }
        
        
        nextFactor = new HashSet<String>();
        firstFactor = null;
        secondFactor = null;
        step = 0;
        timestamp = System.currentTimeMillis();
        
        if (nextFactor.isEmpty())
        {
            for ( String allowedMethod: allowedAuthenticationMethods)
            {
           		nextFactor.add( allowedMethod.substring(0,1));
            }
        }
	}


	public void initializeTacacsCtx(String user, String remoteIp, String serviceProvider) throws InternalErrorException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		IdpConfig config = IdpConfig.getConfig();
		this.remoteIp = remoteIp;
    	hostId = null;
    	currentUser = null;
    	os = "Unknown";
    	browser = "Radius";
    	cpu = null;

    	String system = IdpConfig.getConfig().getSystem().getName();
    	FederationMember fm = config.findIdentityProviderForRelyingParty(publicId);
    	if (fm.getSystem() != null)
    		system = fm.getSystem();

    	Account acc = new RemoteServiceLocator().getServerService().getAccountInfo(user, system);
    	if (acc == null || acc.isDisabled())
    		throw new InternalErrorException("Account is not enabled");
    	if (acc.getType() != AccountType.USER)
    		throw new InternalErrorException("Account is not of type user");
    	
    	this.publicId = serviceProvider;
    	this.user = acc.getOwnerUsers().iterator().next();
    	getUserData(user);

    	updateAllowedAuthenticationMethods();
        if (requestedAuthenticationMethod != null)
        {
        	allowedAuthenticationMethods.retainAll(requestedAuthenticationMethod);
        	if (allowedAuthenticationMethods.isEmpty())
        		throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        	
        }
        
        nextFactor = new HashSet<String>();
        firstFactor = null;
        secondFactor = null;
        step = 0;
        timestamp = System.currentTimeMillis();
        
        if (nextFactor.isEmpty())
        {
            for ( String allowedMethod: allowedAuthenticationMethods)
            {
           		nextFactor.add( allowedMethod.substring(0,1));
            }
        }
	}


	private static void expireOldContexts() {
		synchronized (auths) {
			if (lastPurge < System.currentTimeMillis() - 5 * 60 * 1000) { // Purge every five minutes
				long last = System.currentTimeMillis() - 20 * 60 * 1000; // Expire after twenty minutes
				for (Iterator<Entry<String, AuthenticationContext>> it = auths.entrySet().iterator(); it.hasNext();) {
					Entry<String, AuthenticationContext> entry = it.next();
					if (entry.getValue().created < last || entry.getValue().isFinished())
						it.remove();
				}
				lastPurge = System.currentTimeMillis();
			}
		}
	}


	public String getRadiusState() {
		return radiusState;
	}


	public void setRadiusState(String radiusState) {
		this.radiusState = radiusState;
	}


	public String getRemoteIp() {
		return remoteIp;
	}


	public void setRemoteIp(String remoteIp) {
		this.remoteIp = remoteIp;
	}


	public static void remove(HttpServletRequest req) {
		 req.getSession().removeAttribute("Soffid-Authentication-Context");
   }

	public Collection<UserCredentialChallenge> getPushChallenge() {
		return pushChallenge;
	}


	public void setPushChallenge(Collection<UserCredentialChallenge> pushChallenge) {
		this.pushChallenge = pushChallenge;
	}


	public Date getCertificateWarning() {
		return certificateWarningDone ? null: certificateWarning;
	}


	public void setCertificateWarning(Date certificateWarning) {
		this.certificateWarning = certificateWarning;
	}


	public boolean isCertificateWarningDone() {
		return certificateWarningDone;
	}


	public void setCertificateWarningDone(boolean certificateWarningDone) {
		this.certificateWarningDone = certificateWarningDone;
	}


	public void setRecoverChallenge(RecoverPasswordChallenge challenge) {
		this.recoverChallenge = challenge;
	}


	public RecoverPasswordChallenge getRecoverChallenge() {
		return recoverChallenge;
	}


}
