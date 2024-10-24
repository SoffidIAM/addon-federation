package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.User;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.SecretStoreService;
import com.soffid.iam.sync.service.ServerService;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.session.Session;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class MazingerConnector extends BaseDataConnector {
	Log log = LogFactory.getLog(getClass());
	
    public Map<String, BaseAttribute> resolve(
            ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
    	Long t = System.currentTimeMillis();

    	SAMLProfileRequestContext ctx = resolutionContext.getAttributeRequestContext();
        

        try {
        	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        	IdpConfig config = IdpConfig.getConfig();
            HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
            
            Session session = ctx.getUserSession();
            if (session != null)
            {
            	Subject subject = session.getSubject();
            	if (subject != null)
            	{
            		for (SessionPrincipal principal: subject.getPrincipals(SessionPrincipal.class))
            		{
            			addStringValue(m, "mazingerSecrets", principal.getSessionString());
            		}
            	}
            }
            
            try {
            	String rpid = ctx.getInboundMessageIssuer();
	            User user = server.getUserInfo(ctx.getPrincipalName(), config.getSystem().getName ());
	            addStringValue(m, "mazingerSecrets2", generateSecrets(user, rpid));
            } catch (UnknownUserException e) {
            }

            log.info("Mazinger rules: "+(System.currentTimeMillis()-t));
            return m;
        } catch (Exception e) {
            throw new AttributeResolutionException(e);
		}
    }

    private void addStringValue(HashMap<String, BaseAttribute> m,
            String name, String value) {
        BasicAttribute<String> b = new BasicAttribute<String>(name);
        b.setValues(Collections.singleton(value));
        m.put(name, b);
    }

    public void validate() throws AttributeResolutionException {
    }

	public String generateSecrets(User user, String rpid) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException 
	{
		String system = null;
		FederationMember fm = IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(rpid);
		if (fm != null)
			system = fm.getSystem();
        StringBuffer result = new StringBuffer();
        SecretStoreService sss = new RemoteServiceLocator().getSecretStoreService();
        for (Secret secret : sss.getAllSecrets(user)) {
        	if (secret.getName() != null && secret.getName().length() > 0 &&
        			secret.getValue() != null &&
        			secret.getValue().getPassword() != null &&
        			secret.getValue().getPassword().length() > 0 )
        	{
        		if (system == null || (
        				secret.getName().startsWith("sso."+system+".") || 
        				secret.getName().startsWith("account."+system+".") || 
        				secret.getName().startsWith("accdesc."+system+".") || 
        				secret.getName().startsWith("pass."+system+".") || 
        				secret.getName().startsWith("user") ))  {
        			if (result.length() > 0)
        				result.append('|');
        			result.append( encodeSecret(secret.getName()));
        			result.append('|');
        			result.append( encodeSecret(secret.getValue().getPassword()));
        		}
        	}
        }
        result.append ("|sessionKey|");
       	result.append ("|fullName|").append(encodeSecret(user.getFullName()));
        return result.toString();
    }



	private String encodeSecret(String secret)
			throws UnsupportedEncodingException {
		return secret.replace("\\", "\\\\").replace("|", "\\|"); 
	}
}
