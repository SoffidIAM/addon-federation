package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

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
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.sync.servei.ServerService;

public class DataConnector extends BaseDataConnector {
	
	
	
    public Map<String, BaseAttribute> resolve(
            ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {
        SAMLProfileRequestContext ctx = resolutionContext.getAttributeRequestContext();
        
        String principal = ctx.getPrincipalName();
        
        try {
        	ServerService server = ServerLocator.getInstance().getRemoteServiceLocator().getServerService();
        	IdpConfig config = IdpConfig.getConfig();

        	Usuari ui = server.getUserInfo(principal, config.getDispatcher().getCodi ());
            HashMap<String,BaseAttribute> m = new HashMap<String, BaseAttribute>();
            
            addStringValue (m, "givenname", ui.getNom()); //$NON-NLS-1$
            String surname =ui.getPrimerLlinatge()+(ui.getSegonLlinatge()==null?"":" "+ui.getSegonLlinatge()); //$NON-NLS-1$ //$NON-NLS-2$
            addStringValue (m, "surname", surname); //$NON-NLS-1$
            addStringValue (m, "fullname", surname); //$NON-NLS-1$
            
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
            addStringValue (m, "uid", ui.getCodi()); //$NON-NLS-1$
            
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
