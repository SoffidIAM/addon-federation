package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.TimeZone;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.api.UserData;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.AttributeReference;
import com.soffid.iam.sync.engine.extobj.AttributeReferenceParser;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
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
import es.caib.seycon.util.Base64;

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
        	Account account = server.getAccountInfo(principal, config.getSystem().getName());

            log.info("Got account: "+(System.currentTimeMillis()-t));
        	try {
        		ui = server.getUserInfo(principal, config.getSystem().getName ());
        		uid = evaluateUid (server, rpid, principal, ui);        		
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
        		uid = evaluateUid (server, rpid, principal, null);        		
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
    
    private String evaluateUid(ServerService server, String rpid, String principal, User ui) throws Exception {
    	String uid = ui == null ? principal : ui.getUserName();
    	FederationService fs = new RemoteServiceLocator().getFederacioService();
    	for (FederationMember member: fs.findFederationMemberByEntityGroupAndPublicIdAndTipus("%", rpid, "S"))
    	{
    		if (member.getSystem() != null) {
    			Collection<UserAccount> accounts = new RemoteServiceLocator().getServerService().getUserAccounts(ui.getId(), member.getSystem());
    			if (accounts == null || accounts.isEmpty())
    				throw new SecurityException("Access denied");
    		}
    		if (member.getRoles() != null && !member.getRoles().isEmpty()) {
    			boolean found = false;
    			for (RoleGrant role: new RemoteServiceLocator().getServerService().getUserRoles(ui.getId(), null)) {
    				if (member.getRoles().contains(role.getRoleName()+"@"+role.getSystem())) {
    					found = true;
    					break;
    				}
    			}
    			if (!found)
    				throw new SecurityException("Access denied");
    		}
    		if (member.getUidExpression() != null && ! member.getUidExpression().trim().isEmpty())
    		{
    			ValueObjectMapper mapper = new ValueObjectMapper();
            	IdpConfig config = IdpConfig.getConfig();
    			Account account = server.getAccountInfo(principal, config.getSystem().getName());
    			ExtensibleObject eo = ui == null ? 
    				new AccountExtensibleObject(account, server):
    				new UserExtensibleObject(account, ui, server);
   				uid = (String) new ObjectTranslator(config.getSystem(), server,
    					new java.util.LinkedList<ExtensibleObjectMapping>())
    						.eval(member.getUidExpression(), eo);
    		}
    	}
    	return uid;
    	
	}

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
