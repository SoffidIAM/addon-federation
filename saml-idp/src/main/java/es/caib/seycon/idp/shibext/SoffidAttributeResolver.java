package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Map;
import java.util.TimeZone;

import javax.security.auth.Subject;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import com.soffid.iam.addons.federation.common.Attribute;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;
import com.soffid.iam.api.sso.Secret;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.service.SecretStoreService;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.Security;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML1StringAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.provider.SAML2StringAttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethAttributeResolver;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.AttributeDefinition;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.SimpleAttributeDefinition;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.service.ServiceException;
import edu.internet2.middleware.shibboleth.common.session.Session;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.DummySamlRequestContext;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class SoffidAttributeResolver extends ShibbolethAttributeResolver 
	implements ApplicationContextAware  {
	Log log = LogFactory.getLog(getClass());
	private ApplicationContext ctx;

	Map<String, EntryData> cache = new Hashtable<>();
	
	protected EntryData getData() {
		try {
			EntryData data = cache.get(Security.getCurrentTenantName());
			if (data == null) 
				data = loadData();
			else if (data.lastRefresh < System.currentTimeMillis() - 10000) { // 10 seconds data
				ServerService server = new RemoteServiceLocator().getServerService();
			    String config = server.getConfig("saml.policy.lastchange");
			    long lastUpdate = 0;
			    try {
			    	lastUpdate = Long.decode(config);
			    } catch (Exception e) {}
		        if (lastUpdate > data.lastRefresh - 5000) // 5 seconds clock skew
		        	data = loadData();
		        else
		        	data.lastRefresh = System.currentTimeMillis();
			}
		
			return data;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private EntryData loadData() throws InternalErrorException, IOException, NoSuchAlgorithmException {
		EntryData data = new EntryData();
		data.lastRefresh = System.currentTimeMillis();
		data.attributes = new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null);
		data.definitions = new LinkedList<>();
		
		for (Attribute att: data.attributes) {
			SimpleAttributeDefinition def = new SimpleAttributeDefinition();
			def.setId(att.getShortName());
			SAML1StringAttributeEncoder encoder1 = new SAML1StringAttributeEncoder();
			encoder1.setAttributeName("urn:mace:dir:attribute-def:"+att.getShortName());
			def.getAttributeEncoders().add(encoder1);
			SAML2StringAttributeEncoder encoder2 = new SAML2StringAttributeEncoder();
			encoder2.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
			encoder2.setFriendlyName(att.getShortName());
			encoder2.setAttributeName(att.getOid() == null || att.getOid().trim().isEmpty() ? att.getShortName(): att.getOid());
			if (att.getShortName().equals("uid")) {
				def.setSourceAttributeID("uid");
				def.getDependencyIds().add("seu");
			}
			def.getAttributeEncoders().add(encoder2);
			data.definitions.add(def);
		}
		cache.put(Security.getCurrentTenantName(), data);
    	return data;
	}

	@Override
	public Map<String, BaseAttribute> resolveAttributes(SAMLProfileRequestContext attributeRequestContext)
			throws AttributeResolutionException {
        Long t = System.currentTimeMillis();
        String principal = attributeRequestContext.getPrincipalName();
		Map<String, BaseAttribute> m = super.resolveAttributes(attributeRequestContext);
		m.putAll(resolve(principal, attributeRequestContext));
		return m;
	}

    public Map<String, BaseAttribute> resolve(
    		String principal, SAMLProfileRequestContext ctx)
            throws AttributeResolutionException {
        String rpid = ctx.getInboundMessageIssuer();
        
        Long t = System.currentTimeMillis();
        try {
        	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        	IdpConfig config = IdpConfig.getConfig();
        	
        	attributes = new RemoteServiceLocator().getFederacioService().findAtributs(null, null, null);

        	String uid;
        	HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
        	User ui = null;
        	Account account = server.getAccountInfo(principal, config.getSystem().getName());

        	try {
        		ui = server.getUserInfo(principal, config.getSystem().getName ());
        		int i = ui.getFullName().indexOf(" "+ui.getLastName());
        		if (i > 0)
        		{
        			addStringValue (ctx, m, "GivenName", ui.getFullName().substring(0,i).trim()); //$NON-NLS-1$
        			addStringValue (ctx, m, "Surname", ui.getFullName().substring(i+1).trim()); //$NON-NLS-1$
        		}
        		else
        		{
        			addStringValue (ctx, m, "GivenName", ui.getFirstName()); //$NON-NLS-1$
        			addStringValue (ctx, m, "Surname", ui.getLastName()); //$NON-NLS-1$
        		}
        		addStringValue (ctx, m, "Fullname", ui.getFullName()); //$NON-NLS-1$
        		
        		BasicAttribute<String> b = new BasicAttribute<String>("Surnames"); //$NON-NLS-1$
        		LinkedList<String> l = new LinkedList<String>();
        		l.add(ui.getLastName());
        		if (ui.getMiddleName() != null)
        			l.add (ui.getMiddleName());
        		l.add(ui.getFirstName());
        		addStringValues (ctx, m, "Surnames", l); //$NON-NLS-1$
        		
        		
        		addStringValue (ctx, m, "Surname1", ui.getLastName()); //$NON-NLS-1$
        		addStringValue (ctx, m, "Surname2", ui.getMiddleName()); //$NON-NLS-1$
        		if (ui.getShortName() != null && ! ui.getShortName().trim().isEmpty()) {
        			if (ui.getMailDomain() == null) 
        			{
        				addStringValue (ctx, m, "Email", ui.getShortName()); //$NON-NLS-1$
        				addStringValue (ctx, m, "mail", ui.getShortName()); //$NON-NLS-1$
        			}
        			else
        			{
        				addStringValue (ctx, m, "Email", ui.getShortName()+"@"+ui.getMailDomain()); //$NON-NLS-1$ //$NON-NLS-2$
        				addStringValue (ctx, m, "mail", ui.getShortName()+"@"+ui.getMailDomain()); //$NON-NLS-1$ //$NON-NLS-2$
        			}
        		} else {
        			UserData dada = server.getUserData(ui.getId(), "EMAIL"); //$NON-NLS-1$
        			if (dada != null)
        			{
        				addStringValue (ctx, m, "Email", dada.getValue()); //$NON-NLS-1$
        				addStringValue (ctx, m, "mail", dada.getValue()); //$NON-NLS-1$
        			}
        		}
        		addStringValue (ctx, m, "Group", ui.getPrimaryGroup()); //$NON-NLS-1$
        		addStringValue (ctx, m, "UserType", ui.getUserType()); //$NON-NLS-1$
        		
        		UserData data = server.getUserData(ui.getId(), "PHONE"); //$NON-NLS-1$
        		if (data != null)
        			addStringValue (ctx, m, "TelephoneNumber", data.getValue()); //$NON-NLS-1$
        		
        	} catch (UnknownUserException ex) {
        		addStringValue (ctx, m, "Fullname", account.getDescription()); //$NON-NLS-1$
        		
        		addStringValue (ctx, m, "UserType", account.getPasswordPolicy()); //$NON-NLS-1$
        		
        	}
            Session session = ctx.getUserSession();
            if (session != null)
                addStringValue (ctx, m, "sessionId", session.getSessionID()); //$NON-NLS-1$
            
            SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
            
            if (ui != null)
            	generateSecretAttributes(m, ctx, ui);

            addComputedAttributes(ctx, principal, m, ui, account, server);
            
            return m;
        } catch (Exception e) {
            throw new AttributeResolutionException(e);
		}
    }

	private void generateSecretAttributes(HashMap<String,BaseAttribute> m, SAMLProfileRequestContext ctx, User user) throws Exception {
        Session session = ctx.getUserSession();
        if (session != null)
        {
        	Subject subject = session.getSubject();
        	if (subject != null)
        	{
        		for (SessionPrincipal principal: subject.getPrincipals(SessionPrincipal.class))
        		{
        			addStringValue(ctx, m, "SessionKey", principal.getSessionString());
        		}
        	}
        }
        
	}

	private Collection<Attribute> attributes;
    
	private void addStringValue(SAMLProfileRequestContext ctx, HashMap<String, BaseAttribute> m,
            String name, String value) throws Exception {
		LinkedList<String> l = new LinkedList<String>();
		l.add(value);
    	addStringValues(ctx, m, name, l);
    }
    
    private void addStringValues(SAMLProfileRequestContext ctx, HashMap<String, BaseAttribute> m,
            String name, Collection<String> values) throws Exception {
    	if (!m.containsKey(name))
    	{
            BasicAttribute<String> b = new BasicAttribute<String>(name);
            b.setValues(values);
            m.put(name, b);
            
            AttributeDefinition def = getAttributeDefinitions().get(name);
            if (def != null) {
            	for (AttributeEncoder encoder: def.getAttributeEncoders())
            		b.getEncoders().add(encoder);
            }
    	}
    }
    
    private void addComputedAttributes (SAMLProfileRequestContext ctx, String accountName, HashMap<String, BaseAttribute> m, User ui, Account account,
    		ServerService server) throws Exception
    {
        ExtensibleObject eo = ui == null ?
        		new AccountExtensibleObject(account, server):
        		new UserExtensibleObject(account, ui, server);
        Collection<String> values;

        IdpConfig c = IdpConfig.getConfig();
        ObjectTranslator translator = new ObjectTranslator(c.getSystem(), server, new LinkedList<ExtensibleObjectMapping>());
        

        eo.setAttribute("ctx", ctx);
		for ( Attribute attribute: attributes)
        {
  			if (attribute.getValue() != null && !attribute.getValue().isEmpty())
   			{
  				eo.put("ctx", ctx);
  				DelayedAttribute b = new DelayedAttribute(attribute.getShortName(), translator, eo, attribute, ctx instanceof DummySamlRequestContext);
  				m.put(attribute.getShortName(), b);
        	} else if ("urn:oid:1.3.6.1.4.1.5923.1.5.1.1".equals(attribute.getOid())) {
               	m.put("memberOf",  new RolesDelayedAttribute("memberOf", attribute, server, ui, account));
        	} else if ("urn:oid:1.3.6.1.4.1.22896.3.1.6".equals(attribute.getOid())) {
            	String rpid = ctx.getInboundMessageIssuer();
               	m.put("Secrets",  new SecretsDelayedAttribute("Secrets", ui, attribute, rpid));

        	}
        }
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

	@Override
	public Map<String, AttributeDefinition> getAttributeDefinitions() {
		Map<String, AttributeDefinition> m = super.getAttributeDefinitions();
		Map m2 = new HashMap<>(m);
		for ( AttributeDefinition def: getData().definitions) {
			if (! "uid".equals(def.getId()) &&
				!"mail".equals(def.getId()))
				m2.put(def.getId(), def);
		}
		return m2;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.ctx = applicationContext;
		super.setApplicationContext(applicationContext);
	}
	
    protected void loadContext() throws ServiceException {
    	super.loadContext();
    }
}

class EntryData {
	long lastRefresh;
	Collection<Attribute> attributes;
	Collection<AttributeDefinition> definitions;
}