package es.caib.seycon.idp.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.net.HttpCookie;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.adaptive.ActualAdaptiveEnvironment;
import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.idp.radius.attribute.RadiusAttribute;
import com.soffid.iam.addons.federation.idp.radius.packet.AccessRequest;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.User;
import com.soffid.iam.config.Config;
import com.soffid.iam.utils.ConfigurationCache;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class AuthenticationContext {
	String publicId;
	Set<String> requestedAuthenticationMethod;
	int step;
	String firstFactor;
	String secondFactor;
	Set<String> nextFactor;
	private String user;
	private Set<String> allowedAuthenticationMethods;
	private String remoteIp;
	private String hostId;
	private User currentUser;
	private Account currentAccount;
	private UserCredential newCredential;
	long timestamp = 0;
	private Challenge challenge;

	static Log log = LogFactory.getLog(AuthenticationContext.class);

	private boolean alwaysAskForCredentials;
	private String radiusState;
	private long created; 
	
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
	
	public void initialize (HttpServletRequest request) 
		throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
	{
		IdpConfig config = IdpConfig.getConfig();
    	remoteIp = getClientRequest(request);
    	hostId = null;
    	String cookieName = getHostIdCookieName();
    	if (cookieName != null && request != null && request.getCookies() != null)
    	{
			for (Cookie cookie: request.getCookies())
    			if (cookie.getName().equals(cookieName))
    				hostId = cookie.getValue();
    	}
    	currentUser = null;

    	updateAllowedAuthenticationMethods();
        if (requestedAuthenticationMethod != null)
        {
        	allowedAuthenticationMethods.retainAll(requestedAuthenticationMethod);
        }
        
        if (allowedAuthenticationMethods.isEmpty())
        	throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        
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
    		
    	ActualAdaptiveEnvironment env = new ActualAdaptiveEnvironment(currentUser, remoteIp, hostId);
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
	        if (requestedAuthenticationMethod != null)
	        {
	        	allowedAuthenticationMethods.retainAll(requestedAuthenticationMethod);
	        }
            for ( String allowedMethod: allowedAuthenticationMethods)
            {
           		nextFactor.add( allowedMethod.substring(0,1));
            }
		} else if ( user != null && ! user.equals(currentAccount.getName())){
			throw new InternalErrorException( String.format("Cannot mix credentials of %s and %s", user, currentAccount.getName()));
		}
		
		if (! nextFactor.contains(method))
			throw new InternalErrorException("Authentication method '"+method+"' not allowed. Expected one of '"+method+"'. Allowed methods: "+allowedAuthenticationMethods);

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
    		step = 2;
    		timestamp = System.currentTimeMillis();
    		registerNewCredential();
    		feedRatio(false);
    		if (currentUser != null)
    		{
    			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
    			long f = ubh.getUserFailures(currentUser.getId());
    			ubh.setUserFailures(currentUser.getId(), 0);
    			if (hostId == null && resp != null)
    			{
    				hostId = ubh.registerHost(remoteIp);
    				Cookie c2 = new Cookie(getHostIdCookieName(), hostId);
    				c2.setSecure(true);
    				c2.setMaxAge(Integer.MAX_VALUE);
    				c2.setHttpOnly(true);
    				resp.addCookie(c2);
    			}
    			ubh.registerLogon(currentUser.getId(), remoteIp, hostId);
    		}
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

	private void registerNewCredential() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		if (currentUser !=null && newCredential != null)
		{
			newCredential.setUserId(currentUser.getId());
			IdpConfig.getConfig().getUserCredentialService().create(newCredential);
		}
	}

	public void authenticationFailure (String u) throws IOException, InternalErrorException
	{
		getUserData(u);
		feedRatio(true);
		if (u != null && currentUser != null)
		{
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			long f = ubh.getUserFailures(currentUser.getId());
			ubh.setUserFailures(currentUser.getId(), f+1);
		}
	}
	
	public boolean isLocked (String u) throws IOException, InternalErrorException
	{
		getUserData(u);
		if (currentUser != null)
		{
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			return ubh.isLocked(currentUser.getId());
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

	    if (currentAccount == null || currentAccount.isDisabled())
	    	throw new InternalErrorException("The account "+userName+" is disabled");
	    
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
				hostId = ubh.registerHost(remoteIp);
				Cookie c2 = new Cookie(getHostIdCookieName(), hostId);
				c2.setSecure(true);
				c2.setMaxAge(Integer.MAX_VALUE);
				c2.setHttpOnly(true);
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
	public static AuthenticationContext fromRequest(AccessRequest accessRequest, InetAddress sourceAddress, String publicId) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
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
			auth.initialize(accessRequest, sourceAddress, publicId);
			auths.put(auth.getRadiusState(), auth);
		}
		return auth;
	}


	private void initialize(AccessRequest accessRequest, InetAddress sourceAddress, String publicId) throws InternalErrorException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		IdpConfig config = IdpConfig.getConfig();
    	remoteIp = accessRequest.getAttributeValue("Framed-IP-Address");
    	if (remoteIp == null)
    		remoteIp = sourceAddress.getHostAddress();
    	hostId = null;
    	currentUser = null;
    	this.publicId = publicId;
    	user = accessRequest.getUserName();
    	getUserData(accessRequest.getUserName());

    	updateAllowedAuthenticationMethods();
        if (requestedAuthenticationMethod != null)
        {
        	allowedAuthenticationMethods.retainAll(requestedAuthenticationMethod);
        }
        
        if (allowedAuthenticationMethods.isEmpty())
        	throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        
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


}
