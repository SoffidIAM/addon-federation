package es.caib.seycon.idp.ui.broker;

import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SAMLSSOPostServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/sp-profile/SAML2/POST/SSO"; //$NON-NLS-1$
    private ServletContext context;
    Log log = LogFactory.getLog(getClass());
    
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	HashMap<String, String> map = new java.util.HashMap<String, String> ();
    	for (String p: (Set<String>) req.getParameterMap().keySet()) {
    	   map.put (p, req.getParameter(p));
    	}

    	try {
			IdpConfig cfg = IdpConfig.getConfig();
			FederacioService federacioService = new RemoteServiceLocator().getFederacioService();
			
			SamlValidationResults sl = federacioService.authenticate( cfg.getPublicId(), 
					"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", 
					map, 
					cfg.getFederationMember().getRegisterExternalIdentities() != null &&
					cfg.getFederationMember().getRegisterExternalIdentities().booleanValue());

			if (sl == null )
			{
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	    		if (ctx != null)
	    		{
	    			try {
						ctx.authenticationFailure(ctx.getUser());
					} catch (InternalErrorException e) {
					}
	    		}
				resp.sendRedirect(LoginServlet.URI);
			}
			else if ( !sl.isValid())
			{
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	    		if (ctx != null)
	    		{
	    			try {
						ctx.authenticationFailure(ctx.getUser());
					} catch (InternalErrorException e) {
					}
	    		}
				req.setAttribute("ERROR", sl.getFailureReason());
			    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
			    dispatcher.forward(req, resp);
			}
			else if ( sl.getUser() == null)
			{
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	    		if (ctx != null)
	    		{
	    			try {
						ctx.authenticationFailure(ctx.getUser());
					} catch (InternalErrorException e) {
					}
	    		}
				req.setAttribute("ERROR", String.format("Remote user %s at %s is not registered",
						sl.getPrincipalName(), sl.getIdentityProvider()));
			    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
			    dispatcher.forward(req, resp);
			}
			else
			{
        		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        		ctx.authenticated(sl.getUser().getUserName(), "E", resp);
        		ctx.store(req);
        		if ( ctx.isFinished())
        		{
					Autenticator auth = new Autenticator();
					String account = auth.getUserAccount(sl.getUser().getUserName());
					auth.autenticate2(account, getServletContext(), req, resp, ctx.getUsedMethod(), true);
        		}
        		else
        		{
        		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        		    dispatcher.forward(req, resp);
        		}
			}
		} catch (Exception e) {
			req.setAttribute("ERROR", e.toString());
		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
		    dispatcher.forward(req, resp);
		}
    }
    

}
