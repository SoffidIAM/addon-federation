package es.caib.seycon.idp.ui;

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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.exception.InternalErrorException;

public class AuthenticationMethodFilter {
    String method ;
	private String relyingParty;
	private AuthenticationContext ctx;
    public AuthenticationMethodFilter(HttpServletRequest req) throws ServletException {
        HttpSession s = req.getSession(false);
        if (s == null)
            throw new ServletException("Invalid session"); //$NON-NLS-1$
        method = (String) req.getSession().
                getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
    	relyingParty = (String) req.getSession().
                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
    	ctx = AuthenticationContext.fromRequest(req);
    			
    }
    
    public boolean allowUserPassword () {
        if (ctx == null || ctx.getNextFactor() == null || ctx.getNextFactor().contains("P"))
            return true;
        return false;
    }

    public boolean requiresKerberos () {
        if (ctx == null || ctx.getNextFactor() == null || ctx.getNextFactor().contains("K"))
            return true;
        return false;
    }

    public boolean allowKerberos () {
        if (ctx == null || ctx.getNextFactor() == null || ctx.getNextFactor().contains("K"))
            return true;
        return false;
    }

    public boolean allowTls () {
        if (ctx == null || ctx.getNextFactor() == null || ctx.getNextFactor().contains("C"))
            return true;
    
        return false;
    }

    public boolean allowSignature () {
        return true;
    }

    
    public FederationMember getIdentityProvider() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException
    {
    	
    	IdpConfig config = IdpConfig.getConfig();

    	if (relyingParty == null)
    		throw new InternalErrorException ("Cannot guess relying party");

    	return config.findIdentityProviderForRelyingParty(relyingParty);
    }

	private Set<String> guessAuthenticationMethods(String publicId, String clientId) throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
		IdpConfig config = IdpConfig.getConfig();
		FederationMember fm = guessFederationMember (publicId, clientId);

		HashSet<String> methods = new HashSet<String>(); 
		for ( String s: fm.getAuthenticationMethods().split(" "))
		{
			methods.add(s);
		}
		return methods;

	}

	private FederationMember guessFederationMember(String publicId, String clientId) throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
		IdpConfig config = IdpConfig.getConfig();
		EntityGroupMember m = new EntityGroupMember();
		m.setType("IDP");
		m.setFederationMember(config.getFederationMember());
		m.setEntityGroup( config.getFederationMember().getEntityGroup() );
		for (EntityGroupMember children: config.getFederationService().findChildren(m))
		{
			FederationMember vip = children.getFederationMember();
			for (FederationMember sp: vip.getServiceProvider())
			{
				if (clientId != null && clientId.equals( sp.getOpenidClientId() ) ||
						publicId != null && publicId.equals(sp.getPublicId()))
				{
					return vip;
				}
			}
		}
		return config.getFederationMember();
	}
}
