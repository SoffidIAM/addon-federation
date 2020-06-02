package es.caib.seycon.idp.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.adaptive.ActualAdaptiveEnvironment;
import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.User;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.exception.InternalErrorException;

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
	

	public static AuthenticationContext fromRequest (HttpServletRequest r)
	{
		return (AuthenticationContext) r.getSession().getAttribute("Soffid-Authentication-Context");
	}
	
	public void store (HttpServletRequest r)
	{
		r.getSession().setAttribute("Soffid-Authentication-Context", this);
	}
	
	public AuthenticationContext ()
	{
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
    	remoteIp = request.getRemoteAddr();
    	hostId = null;
    	String cookieName = getHostIdCookieName();
    	if (cookieName != null && request != null && request.getCookies() != null)
    	{
			for (Cookie cookie: request.getCookies())
    			if (cookie.getName().equals(cookieName))
    				hostId = cookie.getValue();
    	}
    	currentUser = null;

    	allowedAuthenticationMethods = findAllowedAuthenticationMethods();
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
        
        if (nextFactor.isEmpty())
        {
            for ( String allowedMethod: allowedAuthenticationMethods)
            {
           		nextFactor.add( allowedMethod.substring(0,1));
            }
        }
	}
	
	public boolean isPreviousAuthenticationMethodAllowed (HttpServletRequest request) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
	{
		HttpSession session = request.getSession(true);
        if (step != 2)
        	return false;

        String method = getUsedMethod();
        
        Set<String> allowed = findAllowedAuthenticationMethods();
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
	
	
	
	private Set<String> findAllowedAuthenticationMethods() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
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
		String m = new RemoteServiceLocator().getUserBehaviorService().getAuthenticationMethod(fm, env );

		HashSet<String> methods = new HashSet<String>(); 
		for ( String s: m.split(" "))
		{
			methods.add(s);
		}
		return methods;

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
		
			allowedAuthenticationMethods = findAllowedAuthenticationMethods();
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
			throw new InternalErrorException("Authentication method not allowed");

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
    		registerNewCredential();
    		feedRatio(false);
    		if (currentUser != null)
    		{
    			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
    			long f = ubh.getUserFailures(currentUser.getId());
    			ubh.setUserFailures(currentUser.getId(), 0);
    			if (hostId == null)
    			{
    				hostId = ubh.registerHost(remoteIp);
    				Cookie c = new Cookie(getHostIdCookieName(), hostId);
    				c.setMaxAge(Integer.MAX_VALUE);
    				resp.addCookie(c);
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

	public void authenticationFailure () throws IOException, InternalErrorException
	{
		feedRatio(true);
		if (currentUser != null)
		{
			UserBehaviorService ubh = new RemoteServiceLocator().getUserBehaviorService();
			long f = ubh.getUserFailures(currentUser.getId());
			ubh.setUserFailures(currentUser.getId(), f+1);
		}
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
	    
	    if (currentAccount != null && currentAccount.getType() == AccountType.USER && currentAccount.getOwnerUsers() != null && currentAccount.getOwnerUsers().size() == 1)
	    	currentUser = currentAccount.getOwnerUsers().iterator().next();
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
}
