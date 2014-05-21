package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.Principal;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.server.session.JDBCSessionManager.Session;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.Password;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.PolicyCheckResult;
import es.caib.seycon.ng.comu.TipusDada;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.servei.DadesAddicionalsService;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class RegisterAction extends HttpServlet {
    public static final String REGISTER_SERVICE_PROVIDER = "RegisterServiceProvider";

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/registerAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        String error = null;
        String un = req.getParameter("userName"); //$NON-NLS-1$
        String gn = req.getParameter("givenName"); //$NON-NLS-1$
        String sn = req.getParameter("surName");
        String email = req.getParameter("email");
        String p1 = req.getParameter("j_password1");
        String p2 = req.getParameter("j_password2");
        
        try  {
            if ( ! amf.getIdentityProvider().isAllowRegister())
            {
        		throw new ServletException ("Not authorized to self register");
            }

            IdpConfig config = IdpConfig.getConfig();
	    	
	    	HttpSession session = req.getSession();
	        
	    	String relyingParty = (String) session.
	                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
	
	    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);
	
	        String userType = ip.getUserTypeToRegister();
	        
	        if (un == null || un.isEmpty())
	        {
	        	error = "User name is required";
	        } else if (un.length() > 10) {
			    error = "User name cannot have more than ten characters";
	        } else if (gn == null || gn.isEmpty()) {
			    error = "Given name is required";
	        } else if (sn == null || sn.isEmpty()) {
			    error = "Surname is required";
	        } else if (email == null || email.isEmpty()) {
			    error = "Email address is required";
	        } else if (! email.contains("@")) {
			    error = "Email address is not valid";
        	} else if (p1 == null || p1.length() == 0) {
	            error = Messages.getString("PasswordChangeRequiredAction.missing.pasword"); //$NON-NLS-1$
	        } else if (p2 == null || p2.length() == 0) {
	            error = Messages.getString("PasswordChangeRequiredAction.missing.second.password"); //$NON-NLS-1$
	        } else if (! p1.equals(p2)) {
	            error = Messages.getString("PasswordChangeRequiredAction.password.mismatch"); //$NON-NLS-1$
	        } else if ( ! ip.isAllowRegister() ){
	        	error = "Register is not allowed";
	        } else {
	       
	            PasswordManager pm = new PasswordManager();
                PolicyCheckResult result = pm.checkPolicy(userType, new Password(p1));
                if (result.isValid())
                {
                	UsuariService usuariService = new RemoteServiceLocator().getUsuariService();
                	DadesAddicionalsService dadesService = new RemoteServiceLocator().getDadesAddicionalsService();
                	Usuari usuari = usuariService.findUsuariByCodiUsuari(un);
                	if (usuari != null)
                		error = String.format("The user name %s is in use. Please, selecte another one", un);
                	else
                	{
                		usuari = new Usuari();
                		usuari.setCodi(un);
                		usuari.setNom(gn);
                		usuari.setPrimerLlinatge(sn);
                		usuari.setActiu(Boolean.FALSE);
                		usuari.setCodiGrupPrimari(ip.getGroupToRegister());
                		usuari.setDataCreacioUsuari(Calendar.getInstance());
                		usuari.setMultiSessio(Boolean.FALSE);
                		usuari.setServidorCorreu("null");
                		usuari.setServidorHome("null");
                		usuari.setServidorPerfil("null");
                		usuari.setTipusUsuari(ip.getUserTypeToRegister());
                		usuari.setComentari(String.format("Self registered from IP %s", req.getRemoteAddr()));
                		
                		Map<String,String> dades = new HashMap<String, String>();
                		dades.put ("EMAIL", email);
                		dades.put (REGISTER_SERVICE_PROVIDER, relyingParty);
                		
                		config.getFederationService().registerUser(config.getDispatcher().getCodi(), usuari, dades, new Password(p1));

                		String url = "https://"+config.getHostName()+":"+config.getStandardPort()+ActivateUserAction.URI
                				+ "?rp="+relyingParty;
                		config.getFederationService().sendActivationEmail(un, 
                				ip.getMailHost(), ip.getMailSenderAddress(), 
                				url, ip.getOrganization());
                	}
                }
                else
                	error = result.getReason();
	        }
        } catch (InternalErrorException e) {
             error = "An internal error has been detected: "+e.getMessage();
             e.printStackTrace();
        } catch (Exception e) {
            error = "An internal error has been detected: "+e.toString();
             e.printStackTrace();
        }
        
        if (error == null)
    	{
	        RequestDispatcher dispatcher = req.getRequestDispatcher(RegisteredFormServlet.URI);
	        dispatcher.forward(req, resp);
    	} else {
	        req.setAttribute("ERROR", error); //$NON-NLS-1$
	        req.setAttribute("previousUserName", un); //$NON-NLS-1$
	        req.setAttribute("previousSurName", sn); //$NON-NLS-1$
	        req.setAttribute("previousGivenName", gn); //$NON-NLS-1$
	        req.setAttribute("previousEmail", email);//$NON-NLS-1$
	        
	        RequestDispatcher dispatcher = req.getRequestDispatcher(RegisterFormServlet.URI);
	        dispatcher.forward(req, resp);
    	}
    }

}
