package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.User;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;

public class ActivateUserAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/activateAction"; //$NON-NLS-1$

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
	        
	    	boolean existingSession;
        	String relyingParty = (String) session.
                    getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
        	if (relyingParty != null)
        		existingSession = true;
        	else
        	{
        		relyingParty = req.getParameter("rp");
        		existingSession = false;
        	}
	
	    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

	    	if (! ip.isAllowRegister())
	    		throw new InternalErrorException ("Registration is not permited");
	    	
	        String key = req.getParameter("key"); //$NON-NLS-1$
	        
	        
      		User u = config.getFederationService().verifyActivationEmail(key);
      		
      		if ( u != null)
      		{
      			new RemoteServiceLocator().getServerService().propagateOBUser(u);
      			if (existingSession)
      			{
      				try {
      					new Autenticator().autenticate2(u.getUserName(), getServletContext(), req, resp, "P", false);
                        return;
      				} catch (Exception e)
      				{
      					
      				}
      			}
      			
				RequestDispatcher dispatcher = req.getRequestDispatcher("profile/SAML2/Unsolicited/SSO?providerId="+
						URLEncoder.encode(relyingParty, "UTF-8"));
		        dispatcher.forward(req, resp);
				return;

      		}
        } catch (InternalErrorException e) {
            error = "Unable to activate account: "+e.getMessage(); //$NON-NLS-1$
        } catch (Exception e) {
             error = "Unable to activate account: "+e.toString(); //$NON-NLS-1$
        }

       
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(ActivatedFormServlet.URI);
        dispatcher.forward(req, resp);
    }

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost(req, resp);
	}

    
}
