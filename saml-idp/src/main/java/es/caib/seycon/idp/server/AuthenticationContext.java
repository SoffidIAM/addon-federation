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
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;

public class AuthenticationContext {
	String publicId;
	Set<String> requestedAuthenticationMethod;
	int step;
	String firstFactor;
	String secondFactor;
	Set<String> nextFactor;
	private String user;
	

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
	
	public void initialize () 
		throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
	{
        Set<String> allowed = findAllowedAuthenticationMethods();
        if (requestedAuthenticationMethod != null)
        	allowed.retainAll(requestedAuthenticationMethod);
        
        if (allowed.isEmpty())
        	throw new InternalErrorException("No common authentication method allowed by client request and system policy");
        
        nextFactor = new HashSet<String>();
        firstFactor = null;
        secondFactor = null;
        step = 0;
        
        if (nextFactor.isEmpty())
        {
            for ( String allowedMethod: allowed)
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
        if (requestedAuthenticationMethod != null)
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

		HashSet<String> methods = new HashSet<String>(); 
		for ( String s: fm.getAuthenticationMethods().split(" "))
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
	
	
	public void authenticated (String user, String method) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
	{
		if (! nextFactor.contains(method))
			throw new InternalErrorException("Authentication method not allowed");

		if (step == 0) 
		{
			this.user = user;
			firstFactor = method;
		}
		else secondFactor = method;
		
		String m = getUsedMethod();
		Set<String> allowed = findAllowedAuthenticationMethods();
		nextFactor.clear();
    	if ( allowed.contains(m))
    		step = 2;
    	else
    	{
    		for ( String allowedMethod: allowed)
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
		requestedAuthenticationMethod = new HashSet<String>();
		for (String method: samlMethods)
		{
			requestedAuthenticationMethod.add( Autenticator.toSoffidAuthenticationMethod(method));
		}
		
	}

}
