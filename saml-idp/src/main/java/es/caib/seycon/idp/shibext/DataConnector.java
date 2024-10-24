package es.caib.seycon.idp.shibext;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.ServerService;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.UnknownUserException;

public class DataConnector extends BaseDataConnector {
	Log log = LogFactory.getLog(getClass());
	private ServerService server;
	
    public Map<String, BaseAttribute> resolve(
            ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
        SAMLProfileRequestContext ctx = resolutionContext.getAttributeRequestContext();
        
        String principal = ctx.getPrincipalName();
        
        String rpid = ctx.getInboundMessageIssuer();
        
        Long t = System.currentTimeMillis();
        try {
        	server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        	IdpConfig config = IdpConfig.getConfig();
        	
        	attributes = new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null);

        	String uid;
        	HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
        	User ui = null;
        	try {
        		ui = server.getUserInfo(principal, config.getSystem().getName ());
        		uid = new UidEvaluator().evaluateUid (server, rpid, principal, ui);        		
        		if (ui.getShortName() != null && ! ui.getShortName().trim().isEmpty()) {
        			if (ui.getMailDomain() == null) 
        			{
        				addStringValue (ctx, m, "mail", ui.getShortName()); //$NON-NLS-1$
        			}
        			else
        			{
        				addStringValue (ctx, m, "mail", ui.getShortName()+"@"+ui.getMailDomain()); //$NON-NLS-1$ //$NON-NLS-2$
        			}
        		} else {
        			UserData dada = server.getUserData(ui.getId(), "EMAIL"); //$NON-NLS-1$
        			if (dada != null)
        			{
        				addStringValue (ctx, m, "mail", dada.getValue()); //$NON-NLS-1$
        			}
        		}
        	} catch (UnknownUserException ex) {
        		uid = new UidEvaluator().evaluateUid (server, rpid, principal, null);        		
        	}

        	ctx.setPrincipalName(uid);
            addStringValue (ctx, m, "uid", uid); //$NON-NLS-1$

            return m;
        } catch (SecurityException e) {
        	throw e;
        } catch (Exception e) {
            throw new AttributeResolutionException(e);
		}
    }

	private Collection<Attribute> attributes;
    

	@Override
	public void validate() throws AttributeResolutionException {
	}

	private void addStringValue(SAMLProfileRequestContext ctx, HashMap<String, BaseAttribute> m,
            String name, String value) throws Exception {
    	addStringValues(ctx, m, name.toLowerCase(), Collections.singleton(value));
    }
    
    private void addStringValues(SAMLProfileRequestContext ctx, HashMap<String, BaseAttribute> m,
            String name, Collection<String> values) throws Exception {
    	if (!m.containsKey(name))
    	{
            BasicAttribute<String> b = new BasicAttribute<String>(name);
            b.setValues(values);
            m.put(name, b);
    	}
    }

}
