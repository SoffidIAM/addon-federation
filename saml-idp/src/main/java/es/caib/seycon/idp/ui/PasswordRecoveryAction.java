package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.Principal;
import java.util.Calendar;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.eclipse.jetty.server.session.JDBCSessionManager.Session;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.metadata.EntityDescriptor;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.Password;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.PolicyCheckResult;
import es.caib.seycon.ng.comu.TipusDada;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.servei.DadesAddicionalsService;
import es.caib.seycon.ng.servei.UsuariService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordRecoveryAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/passwordRecoveryAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        String error = null;
        try  {
	    	IdpConfig config = IdpConfig.getConfig();
	    	
	    	HttpSession session = req.getSession();
	        
	    	String relyingParty = (String) session.
	                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
	
	    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

	    	if (! ip.isAllowRecover())
	    		throw new InternalErrorException ("Registration is not permited");
	    	
	        String email = req.getParameter("email"); //$NON-NLS-1$
	        
    		String url = "https://"+config.getHostName()+":"+config.getStandardPort()+PasswordRecoveryAction2.URI;

      		config.getFederationService().sendRecoverEmail(email, 
      				ip.getMailHost(), ip.getMailSenderAddress(), 
      				url, ip.getOrganization());
      		
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordRecoveryForm.URI);
            dispatcher.forward(req, resp);
            return;
        } catch (InternalErrorException e) {
            error = "Unable to activate account: "+e.getMessage(); //$NON-NLS-1$
        } catch (Exception e) {
             error = "Unable to activate account: "+e.toString(); //$NON-NLS-1$
        }

       
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(ErrorServlet.URI);
        dispatcher.forward(req, resp);
    }

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost(req, resp);
	}

    
}
