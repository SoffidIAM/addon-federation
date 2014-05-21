package es.caib.seycon.idp.shibext;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.Subject;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.session.Session;

public class MazingerConnector extends BaseDataConnector {

    public Map<String, BaseAttribute> resolve(
            ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
        SAMLProfileRequestContext ctx = resolutionContext.getAttributeRequestContext();
        
        try {
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

}
