package es.caib.seycon.idp.ui.oauth;

import java.io.IOException;

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

import es.caib.seycon.idp.oauth.consumer.OAuth2Consumer;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.exception.InternalErrorException;

public class OauthResponseAction extends HttpServlet {
    public static final String REGISTER_SERVICE_PROVIDER = "RegisterServiceProvider";

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/oauthResponse"; //$NON-NLS-1$

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
	        
	        OAuth2Consumer consumer = OAuth2Consumer.fromSesssion(session);
	        
	        if (consumer == null)
	        {
	        	generateError (req, resp, "Your session has been expired. Unexpected oAuth response");
	        	return;
	        }
	        
	        if (! consumer.verifyResponse(req))
	        {
	        	generateError (req, resp, "Authentication failed");
	        	return;
	        }

	        
   			User u = new RemoteServiceLocator().getFederacioService().findAccountOwner(consumer.getPrincipal (), 
   					consumer.getRelyingParty(), 
   					consumer.getAttributes(), 
   					ip.getRegisterExternalIdentities() != null && ip.getRegisterExternalIdentities().booleanValue());

   			if (u == null)
   				throw new InternalErrorException("Not authorized");

    		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
    		Autenticator auth = new Autenticator();
    		String account = auth.getUserAccount(u.getUserName());
    		ctx.authenticated(account, "E");
    		ctx.store(req);
    		if ( ctx.isFinished())
    		{
	            auth.autenticate2(account, getServletContext(), req, resp, ctx.getUsedMethod(), consumer.getRelyingParty(), true);
    		} else {
    		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
    		    dispatcher.forward(req, resp);
    		}
		} catch (InternalErrorException e) {
			generateError(req, resp, e.getMessage());
		} catch (Exception e) {
			throw new ServletException (e);
		}
    }

}
