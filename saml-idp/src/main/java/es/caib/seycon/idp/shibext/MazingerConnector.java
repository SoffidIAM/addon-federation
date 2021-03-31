package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.User;
import com.soffid.iam.api.sso.Secret;
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

    public Map<String, BaseAttribute> resolve(
            ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
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
	            User user = server.getUserInfo(ctx.getPrincipalName(), config.getSystem().getName ());
	            addStringValue(m, "mazingerSecrets2", generateSecrets(user));
            } catch (UnknownUserException e) {
            }
            
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

	public String generateSecrets(User user) throws IOException, InternalErrorException 
	{
        StringBuffer result = new StringBuffer();
        SecretStoreService sss = new RemoteServiceLocator().getSecretStoreService();
        for (Secret secret : sss.getAllSecrets(user)) {
        	if (secret.getName() != null && secret.getName().length() > 0 &&
        			secret.getValue() != null &&
        			secret.getValue().getPassword() != null &&
        			secret.getValue().getPassword().length() > 0 )
        	{
        		if (result.length() > 0)
        			result.append('|');
               	result.append( encodeSecret(secret.getName()));
                result.append('|');
                result.append( encodeSecret(secret.getValue().getPassword()));
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
