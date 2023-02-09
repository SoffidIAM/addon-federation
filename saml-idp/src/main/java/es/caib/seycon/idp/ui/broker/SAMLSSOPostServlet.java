package es.caib.seycon.idp.ui.broker;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;
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
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.System;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.service.AccountService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.exception.AccountAlreadyExistsException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.NeedsAccountNameException;
import es.caib.seycon.util.Base64;

public class SAMLSSOPostServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/sp-profile/SAML2/POST/SSO"; //$NON-NLS-1$
    private ServletContext context;
    Log log = LogFactory.getLog(getClass());
   
    static HashMap<String,HashMap<String,String>> requests = new HashMap<>();  
    
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException {
    	HashMap<String, String> map = new java.util.HashMap<String, String> ();
    	for (String p: (Set<String>) req.getParameterMap().keySet()) {
    		map.put (p, req.getParameter(p));
    	}
    	
    	String t;
    	do {
	    	byte[] b = new byte[16];
	    	new SecureRandom().nextBytes(b);
	    	t = Base64.encodeBytes(b, Base64.DONT_BREAK_LINES);
    	} while (requests.containsKey(t));
    	requests.put(t, map);
    	resp.sendRedirect(URI+"?request="+ URLEncoder.encode(t, "UTF-8"));
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String t = req.getParameter("request");
    	HashMap<String, String> map = requests.get(t);
    	requests.remove(t);
    	if (t == null)
    	{
			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
            LogFactory.getLog(getClass()).info("Error validating saml request");
		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
		    dispatcher.forward(req, resp);
		    return;
    	}
    	try {
			IdpConfig cfg = IdpConfig.getConfig();
			FederationService federacioService = new RemoteServiceLocator().getFederacioService();
			
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
        		String accountName = findIdpAccount(sl.getUser(), cfg.getSystem());
        		ctx.authenticated(accountName, "E", resp);
        		ctx.store(req);
        		if ( ctx.isFinished())
        		{
					Autenticator auth = new Autenticator();
					String account = auth.getUserAccount(sl.getUser().getUserName());
					auth.autenticate2(accountName, getServletContext(), req, resp, ctx.getUsedMethod(), true, ctx.getHostId(resp));
        		}
        		else
        		{
        		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        		    dispatcher.forward(req, resp);
        		}
			}
		} catch (Exception e) {
			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
            LogFactory.getLog(getClass()).info("Error validating saml request ", e);
		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
		    dispatcher.forward(req, resp);
		}
    }

	private String findIdpAccount(User user, System system) throws InternalErrorException, NeedsAccountNameException, AccountAlreadyExistsException, IOException {
		final AccountService accountService = new RemoteServiceLocator().getAccountService();
		for (UserAccount account: accountService.findUsersAccounts(user.getUserName(),  system.getName())) {
			return account.getName();
		}
		UserAccount acc = accountService.createAccount(user, system, null);
		return acc.getName();
	}
    

}
