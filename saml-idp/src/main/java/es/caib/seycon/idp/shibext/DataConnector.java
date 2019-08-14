package es.caib.seycon.idp.shibext;

import java.io.IOException;
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

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
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
	
	
	
    public Map<String, BaseAttribute> resolve(
            ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
        SAMLProfileRequestContext ctx = resolutionContext.getAttributeRequestContext();
        
        String principal = ctx.getPrincipalName();
        
        String rpid = ctx.getInboundMessageIssuer();
        
        try {
        	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        	IdpConfig config = IdpConfig.getConfig();
        	attributes = new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null);

        	String uid;
        	HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
        	try {
        		User ui = server.getUserInfo(principal, config.getSystem().getName ());
        		uid = evaluateUid (server, rpid, principal, ui);        		
        		int i = ui.getFullName().indexOf(" "+ui.getLastName());
        		if (i > 0)
        		{
        			addStringValue (ctx, m, "givenname", ui.getFullName().substring(0,i).trim()); //$NON-NLS-1$
        			addStringValue (ctx, m, "surname", ui.getFullName().substring(i+1).trim()); //$NON-NLS-1$
        		}
        		else
        		{
        			addStringValue (ctx, m, "givenname", ui.getFirstName()); //$NON-NLS-1$
        			addStringValue (ctx, m, "surname", ui.getLastName()); //$NON-NLS-1$
        		}
        		addStringValue (ctx, m, "fullname", ui.getFullName()); //$NON-NLS-1$
        		
        		BasicAttribute<String> b = new BasicAttribute<String>("surnames"); //$NON-NLS-1$
        		LinkedList<String> l = new LinkedList<String>();
        		l.add(ui.getLastName());
        		if (ui.getMiddleName() != null)
        			l.add (ui.getMiddleName());
        		l.add(ui.getFirstName());
        		addStringValues (ctx, m, "surnames", l); //$NON-NLS-1$
        		
        		
        		addStringValue (ctx, m, "surname1", ui.getLastName()); //$NON-NLS-1$
        		addStringValue (ctx, m, "surname2", ui.getMiddleName()); //$NON-NLS-1$
        		if (ui.getShortName() != null) {
        			if (ui.getMailDomain() == null) 
        				addStringValue (ctx, m, "email", ui.getShortName()); //$NON-NLS-1$
        			else
        				addStringValue (ctx, m, "email", ui.getShortName()+"@"+ui.getMailDomain()); //$NON-NLS-1$ //$NON-NLS-2$
        		} else {
        			UserData dada = server.getUserData(ui.getId(), "EMAIL"); //$NON-NLS-1$
        			if (dada != null)
        				addStringValue (ctx, m, "email", dada.getValue()); //$NON-NLS-1$
        		}
        		addStringValue (ctx, m, "group", ui.getPrimaryGroup()); //$NON-NLS-1$
        		addStringValue (ctx, m, "userType", ui.getUserType()); //$NON-NLS-1$
        		
        		UserData data = server.getUserData(ui.getId(), "PHONE"); //$NON-NLS-1$
        		if (data != null)
        			addStringValue (ctx, m, "telephoneNumber", data.getValue()); //$NON-NLS-1$
        		
        		if (!m.containsKey("memberof"))
        			collectRoles (m, server, ui);
        	} catch (UnknownUserException ex) {
        		uid = evaluateUid (server, rpid, principal, null);        		

        		Account account = server.getAccountInfo(principal, config.getSystem().getName());
        		addStringValue (ctx, m, "fullname", account.getDescription()); //$NON-NLS-1$
        		
        		addStringValue (ctx, m, "userType", account.getPasswordPolicy()); //$NON-NLS-1$
        		
        		if (!m.containsKey("memberof"))
        			collectRoles (m, server, account);
        	}

        	ctx.setPrincipalName(uid);
            addStringValue (ctx, m, "uid", uid); //$NON-NLS-1$
            
            addComputedAttributes(ctx, m);
            
            Session session = ctx.getUserSession();
            if (session != null)
                addStringValue (ctx, m, "sessionId", session.getSessionID()); //$NON-NLS-1$
            
            SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
            
            return m;
        } catch (Exception e) {
            throw new AttributeResolutionException(e);
		}
    }

    org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
	private Collection<Attribute> attributes;
    
    private String evaluateUid(ServerService server, String rpid, String principal, User ui) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
    	String uid = ui == null ? principal : ui.getUserName();
    	FederacioService fs = new RemoteServiceLocator().getFederacioService();
    	for (FederationMember member: fs.findFederationMemberByEntityGroupAndPublicIdAndTipus("%", rpid, "S"))
    	{
    		if (member.getUidExpression() != null && ! member.getUidExpression().trim().isEmpty())
    		{
    			ValueObjectMapper mapper = new ValueObjectMapper();
            	IdpConfig config = IdpConfig.getConfig();
    			Account account = server.getAccountInfo(principal, config.getSystem().getName());
    			ExtensibleObject eo = ui == null ? 
    				new AccountExtensibleObject(account, server):
    				new UserExtensibleObject(account, ui, server);
    			String result = (String) new ObjectTranslator(config.getSystem(), server,
    					new java.util.LinkedList<ExtensibleObjectMapping>())
    				.eval(member.getUidExpression(), eo);
    			uid = result;
    		}
    	}
    	return uid;
    	
	}

	private void collectRoles(HashMap<String, BaseAttribute> m, ServerService server,
            User ui) throws RemoteException, InternalErrorException, UnknownUserException {
        Collection<RoleGrant> roles = server.getUserRoles(ui.getId(), null);
        BasicAttribute<String> b = new BasicAttribute<String>("memberOf"); //$NON-NLS-1$
        LinkedList<String> l = new LinkedList<String>();
        for (RoleGrant role : roles) {
            String v =role.getRoleName();
            if (role.getDomainValue() != null && role.getDomainValue().length() > 0)
                v += "/" + role.getDomainValue(); //$NON-NLS-1$
            v += "@"+role.getSystem(); //$NON-NLS-1$
            l.add(v);
        }
        b.setValues(l);
        m.put("memberOf", b); //$NON-NLS-1$
        
        
    }

	private void collectRoles(HashMap<String, BaseAttribute> m, ServerService server,
            Account acc) throws RemoteException, InternalErrorException, UnknownUserException {
        Collection<RoleGrant> roles = server.getAccountRoles(acc.getName(), acc.getSystem());
        BasicAttribute<String> b = new BasicAttribute<String>("memberOf"); //$NON-NLS-1$
        LinkedList<String> l = new LinkedList<String>();
        for (RoleGrant role : roles) {
            String v =role.getRoleName();
            if (role.getDomainValue() != null && role.getDomainValue().length() > 0)
                v += "/" + role.getDomainValue(); //$NON-NLS-1$
            v += "@"+role.getSystem(); //$NON-NLS-1$
            l.add(v);
        }
        b.setValues(l);
        m.put("memberOf", b); //$NON-NLS-1$
        
        
    }

	private void addStringValue(SAMLProfileRequestContext ctx, HashMap<String, BaseAttribute> m,
            String name, String value) throws Exception {
    	addStringValues(ctx, m, name, Collections.singleton(value));
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
    
    private void addComputedAttributes (SAMLProfileRequestContext ctx, HashMap<String, BaseAttribute> m) throws Exception
    {
        Collection<String> values;
		for ( Attribute attribute: attributes)
        {
  			if (attribute.getValue() != null && !attribute.getValue().isEmpty())
   			{
   				BasicAttribute<String> b = new BasicAttribute<String>(attribute.getShortName().toLowerCase());
      			values = evaluate (ctx, attribute);
      			if (values != null)
      				addStringValues(ctx, m, attribute.getShortName().toLowerCase(), values);
        	}
        }
    }

    private Collection<String> evaluate(SAMLProfileRequestContext ctx, Attribute attribute) throws Exception{
        IdpConfig c = IdpConfig.getConfig();
    	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        ObjectTranslator translator = new ObjectTranslator(c.getSystem(), server, new LinkedList<ExtensibleObjectMapping>());

        String principal = ctx.getPrincipalName();
        Account account = server.getAccountInfo(principal, c.getSystem().getName());
        ExtensibleObject eo;
        Object r = null;
        try {
        	User user = server.getUserInfo(principal, c.getSystem().getName());
        	eo = new UserExtensibleObject(account, user, server);
        	r = translator.eval(attribute.getValue(), eo);
        } catch (UnknownUserException e) {
        	eo = new AccountExtensibleObject(account, server);
        	try {
            	r = translator.eval(attribute.getValue(), eo);
        	} 
        	catch (Exception ex)
        	{
        		log.warn("Error evaluating attribute "+attribute.getName(), ex);
        	}
        }
        if (r == null)
        	return null;
        else if (r instanceof Collection)
        	return (Collection<String>) r;
        else if (r instanceof byte[])
         	return Collections.singleton( Base64.encodeBytes((byte[]) r, Base64.DONT_BREAK_LINES) );
        else  
        	return Collections.singleton( new ValueObjectMapper().toSingleString(r) );
	}

	public void validate() throws AttributeResolutionException {
    }

}
