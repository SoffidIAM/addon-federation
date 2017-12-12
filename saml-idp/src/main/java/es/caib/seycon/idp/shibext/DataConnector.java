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
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.session.Session;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;

import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ValueObjectMapper;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.service.ServerService;

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

        	User ui = server.getUserInfo(principal, config.getSystem().getName ());
            HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
            
            int i = ui.getFullName().indexOf(" "+ui.getLastName());
            if (i > 0)
            {
	            addStringValue (m, "givenname", ui.getFullName().substring(0,i).trim()); //$NON-NLS-1$
	            addStringValue (m, "surname", ui.getFullName().substring(i+1).trim()); //$NON-NLS-1$
            }
            else
            {
	            addStringValue (m, "givenname", ui.getFirstName()); //$NON-NLS-1$
	            addStringValue (m, "surname", ui.getLastName()); //$NON-NLS-1$
            }
            addStringValue (m, "fullname", ui.getFullName()); //$NON-NLS-1$
            
            BasicAttribute<String> b = new BasicAttribute<String>("surnames"); //$NON-NLS-1$
            LinkedList<String> l = new LinkedList<String>();
            l.add(ui.getLastName());
            if (ui.getMiddleName() != null)
                l.add (ui.getMiddleName());
            l.add(ui.getFirstName());
            b.setValues(l);
            m.put("surnames", b); //$NON-NLS-1$

           
            addStringValue (m, "surname1", ui.getLastName()); //$NON-NLS-1$
            addStringValue (m, "surname2", ui.getMiddleName()); //$NON-NLS-1$
            if (ui.getShortName() != null) {
                if (ui.getMailDomain() == null) 
                    addStringValue (m, "email", ui.getShortName()); //$NON-NLS-1$
                else
                    addStringValue (m, "email", ui.getShortName()+"@"+ui.getMailDomain()); //$NON-NLS-1$ //$NON-NLS-2$
            } else {
                UserData dada = server.getUserData(ui.getId(), "EMAIL"); //$NON-NLS-1$
                if (dada != null)
                    addStringValue (m, "email", dada.getValue()); //$NON-NLS-1$
            }
            addStringValue (m, "group", ui.getPrimaryGroup()); //$NON-NLS-1$
            addStringValue (m, "userType", ui.getUserType()); //$NON-NLS-1$
            String uid = evaluateUid (server, rpid, principal, ui);
			addStringValue (m, "uid", uid); //$NON-NLS-1$
			ctx.setPrincipalName(uid);

			UserData data = server.getUserData(ui.getId(), "PHONE"); //$NON-NLS-1$
            if (data != null)
            	addStringValue (m, "telephoneNumber", data.getValue()); //$NON-NLS-1$
            
            collectRoles (m, server, ui);
            
            Session session = ctx.getUserSession();
            if (session != null)
                addStringValue (m, "sessionId", session.getSessionID()); //$NON-NLS-1$
            
            SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
            
            for (UserData d: server.getUserData(ui.getId()))
            {
            	if (d.getDateValue() != null)
            	{
            		addStringValue(m, "custom:"+d.getAttribute(), simpleDf.format(d.getDateValue().getTime()));
            	}
            	else if (d.getValue() != null)
            	{
            		addStringValue(m, "custom:"+d.getAttribute(), d.getValue());
            	}
            }
            return m;
        } catch (Exception e) {
            throw new AttributeResolutionException(e);
		}
    }

    org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
    
    private String evaluateUid(ServerService server, String rpid, String principal, User ui) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
    	String uid = ui.getUserName();
    	log.info("Searching uid for relaying party "+rpid);
    	FederacioService fs = new RemoteServiceLocator().getFederacioService();
    	for (FederationMember member: fs.findFederationMemberByEntityGroupAndPublicIdAndTipus("%", rpid, "S"))
    	{
    		if (member.getUidExpression() != null && ! member.getUidExpression().trim().isEmpty())
    		{
    			log.info("Evaluating expression "+member.getUidExpression());
    			ValueObjectMapper mapper = new ValueObjectMapper();
            	IdpConfig config = IdpConfig.getConfig();
    			Account account = server.getAccountInfo(principal, config.getSystem().getName());
    			UserExtensibleObject eo = new UserExtensibleObject(account, ui, server);
    			String result = (String) new ObjectTranslator(config.getSystem(), server,
    					new java.util.LinkedList<ExtensibleObjectMapping>())
    				.eval(member.getUidExpression(), eo);
    			uid = result;
    		}
    	}
		log.info("UID="+uid);
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

    private void addStringValue(HashMap<String, BaseAttribute> m,
            String name, String value) {
        BasicAttribute<String> b = new BasicAttribute<String>(name);
        b.setValues(Collections.singleton(value));
        m.put(name, b);
    }

    public void validate() throws AttributeResolutionException {
    }

}
