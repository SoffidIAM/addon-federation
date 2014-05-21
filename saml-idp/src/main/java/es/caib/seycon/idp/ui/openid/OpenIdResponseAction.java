package es.caib.seycon.idp.ui.openid;

import java.io.IOException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.openid4java.discovery.Identifier;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.consumer.OpenidConsumer;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.comu.sso.NameParser;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class OpenIdResponseAction extends HttpServlet {
    public static final String REGISTER_SERVICE_PROVIDER = "RegisterServiceProvider";

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/openIdResponse"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	doPost(req, resp);
    }
    
    void generateError (HttpServletRequest req, HttpServletResponse resp, String msg) throws ServletException, IOException
    { 
    	req.setAttribute ("ERROR", msg);
    	req.getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        HttpSession session = req.getSession();
        resp.addHeader("Cache-Control", "no-cache"); //$NON-NLS-1$ //$NON-NLS-2$

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        FederationMember ip;
		try {
			ip = amf.getIdentityProvider();
        
	        if (ip == null) 
	        {
	        	generateError (req, resp, "Unable to guess identity provider");
	        	return;
	        }
	        
	        OpenidConsumer consumer = OpenidConsumer.fromSesssion(session);
	        
	        if (consumer == null)
	        {
	        	generateError (req, resp, "Your session has been expired. Unexpected OpenID response");
	        	return;
	        }
	        
	        Identifier id = consumer.verifyResponse(req);
	        
	        if (id == null)
	        {
	        	generateError (req, resp, "Authentication failed");
	        	return;
	        }

	        
	    	LogonService logonService = new RemoteServiceLocator().getLogonService();
	    	ServerService serverService = new RemoteServiceLocator().getServerService();
	        
	    	Usuari usuari;
	    	try {
	    		usuari = serverService.getUserInfo(id.getIdentifier(), IdpConfig.getConfig().getDispatcher().getCodi());
	    
	    	}
	    	catch (es.caib.seycon.ng.exception.UnknownUserException e)
	        {
	    		if (! ip.isAllowRegister())
	    		{
		        	generateError (req, resp, "Not authorized to register as a new user");
	    			return;
	    		}
	    		else
	    		{
            		usuari = new Usuari();
            		usuari.setCodi("?");
            		if (consumer.getFullName() != null)
            		{
            			usuari.setFullName(consumer.getFullName());
            			NameParser np = new NameParser();
            			String name [] = np.parse(consumer.getFullName(), 2);
            			if (name.length >= 1)
            				usuari.setNom(name[0]);
            			if (name.length >= 2)
            				usuari.setPrimerLlinatge(name[1]);
            		}
            		if (consumer.getFirstName() != null)
            			usuari.setNom(consumer.getFirstName());
            		if (consumer.getLastName() != null)
            			usuari.setPrimerLlinatge(consumer.getLastName());
            		
            		if (usuari.getNom() == null)
            			usuari.setNom("?");
            		if (usuari.getPrimerLlinatge() == null)
            			usuari.setPrimerLlinatge("?");
            		
            		usuari.setActiu(Boolean.TRUE);
            		usuari.setCodiGrupPrimari(ip.getGroupToRegister());
            		usuari.setDataCreacioUsuari(Calendar.getInstance());
            		usuari.setMultiSessio(Boolean.FALSE);
            		usuari.setServidorCorreu("null");
            		usuari.setServidorHome("null");
            		usuari.setServidorPerfil("null");
            		usuari.setTipusUsuari(ip.getUserTypeToRegister());
            		usuari.setComentari(String.format("OpenID registered from IP %s", req.getRemoteAddr()));
            		
            		Map<String,String> dades = new HashMap<String, String>();
            		dades.put ("EMAIL", consumer.getEmail());
            		dades.put (REGISTER_SERVICE_PROVIDER, consumer.getRelyingParty());
            		
            		IdpConfig config = IdpConfig.getConfig();
            		
            		usuari = config.getFederationService().registerOpenidUser(id.getIdentifier(), config.getDispatcher().getCodi(), usuari, dades);
            		
          			new RemoteServiceLocator().getServerService().propagateOBUser(usuari);

	    		}
	        	
	        }
	    	
            new Autenticator().autenticate(id.getIdentifier(), req, resp, AuthnContext.UNSPECIFIED_AUTHN_CTX, "OpenID "+consumer.getRelyingParty(), true);

		} catch (InternalErrorException e) {
			generateError(req, resp, e.getMessage());
		} catch (Exception e) {
			throw new ServletException (e);
		}
    }

}
