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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.util.log.Log;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;

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
import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.sync.engine.extobj.ObjectTranslator;
import es.caib.seycon.ng.sync.engine.extobj.UserExtensibleObject;
import es.caib.seycon.ng.sync.engine.extobj.ValueObjectMapper;
import es.caib.seycon.ng.sync.intf.ExtensibleObjectMapping;
import es.caib.seycon.ng.sync.servei.ServerService;

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

        	Usuari ui = server.getUserInfo(principal, config.getDispatcher().getCodi ());
            HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
            
            addStringValue (m, "givenname", ui.getNom()); //$NON-NLS-1$
            String surname =ui.getPrimerLlinatge()+(ui.getSegonLlinatge()==null?"":" "+ui.getSegonLlinatge()); //$NON-NLS-1$ //$NON-NLS-2$
            addStringValue (m, "surname", surname); //$NON-NLS-1$
            addStringValue (m, "fullname", ui.getFullName()); //$NON-NLS-1$
            
            BasicAttribute<String> b = new BasicAttribute<String>("surnames"); //$NON-NLS-1$
            LinkedList<String> l = new LinkedList<String>();
            l.add(ui.getPrimerLlinatge());
            if (ui.getSegonLlinatge() != null)
                l.add (ui.getSegonLlinatge());
            b.setValues(l);
            m.put("surnames", b); //$NON-NLS-1$

            
            addStringValue (m, "surname1", ui.getPrimerLlinatge()); //$NON-NLS-1$
            addStringValue (m, "surname2", ui.getSegonLlinatge()); //$NON-NLS-1$
            if (ui.getNomCurt() != null) {
                if (ui.getDominiCorreu() == null) 
                    addStringValue (m, "email", ui.getNomCurt()); //$NON-NLS-1$
                else
                    addStringValue (m, "email", ui.getNomCurt()+"@"+ui.getDominiCorreu()); //$NON-NLS-1$ //$NON-NLS-2$
            } else {
                DadaUsuari dada = server.getUserData(ui.getId(), "EMAIL"); //$NON-NLS-1$
                if (dada != null)
                    addStringValue (m, "email", dada.getValorDada()); //$NON-NLS-1$
            }
            addStringValue (m, "group", ui.getCodiGrupPrimari()); //$NON-NLS-1$
            addStringValue (m, "userType", ui.getTipusUsuari()); //$NON-NLS-1$
            String uid = evaluateUid (server, rpid, principal, ui);
			addStringValue (m, "uid", uid); //$NON-NLS-1$
			ctx.setPrincipalName(uid);

			DadaUsuari data = server.getUserData(ui.getId(), "TELÈFON"); //$NON-NLS-1$
            if (data == null)
            	 data = server.getUserData(ui.getId(), "PHONE"); //$NON-NLS-1$
            if (data != null)
            	addStringValue (m, "telephoneNumber", data.getValorDada()); //$NON-NLS-1$
            
            collectRoles (m, server, ui);
            
            Session session = ctx.getUserSession();
            if (session != null)
                addStringValue (m, "sessionId", session.getSessionID()); //$NON-NLS-1$
            return m;
        } catch (Exception e) {
            throw new AttributeResolutionException(e);
		}
    }

    org.apache.commons.logging.Log log = LogFactory.getLog(getClass());
    
    private String evaluateUid(ServerService server, String rpid, String principal, Usuari ui) throws IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
    	String uid = ui.getCodi();
    	log.info("Searching uid for relaying party "+rpid);
    	FederacioService fs = new RemoteServiceLocator().getFederacioService();
    	for (FederationMember member: fs.findFederationMemberByEntityGroupAndPublicIdAndTipus("%", rpid, "S"))
    	{
    		if (member.getUidExpression() != null && ! member.getUidExpression().trim().isEmpty())
    		{
    			log.info("Evaluating expression "+member.getUidExpression());
    			ValueObjectMapper mapper = new ValueObjectMapper();
            	IdpConfig config = IdpConfig.getConfig();
    			Account account = server.getAccountInfo(principal, config.getDispatcher().getCodi());
    			UserExtensibleObject eo = new UserExtensibleObject(account, ui, server);
    			String result = (String) new ObjectTranslator(config.getDispatcher(), server,
    					new java.util.LinkedList<ExtensibleObjectMapping>())
    				.eval(member.getUidExpression(), eo);
    			uid = result;
    		}
    	}
		log.info("UID="+uid);
    	return uid;
    	
	}

	private void collectRoles(HashMap<String, BaseAttribute> m, ServerService server,
            Usuari ui) throws RemoteException, InternalErrorException, UnknownUserException {
        Collection<RolGrant> roles = server.getUserRoles(ui.getId(), null);
        BasicAttribute<String> b = new BasicAttribute<String>("memberOf"); //$NON-NLS-1$
        LinkedList<String> l = new LinkedList<String>();
        for (RolGrant role : roles) {
            String v =role.getRolName();
            if (role.getDomainValue() != null && role.getDomainValue().length() > 0)
                v += "/" + role.getDomainValue(); //$NON-NLS-1$
            v += "@"+role.getDispatcher(); //$NON-NLS-1$
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
