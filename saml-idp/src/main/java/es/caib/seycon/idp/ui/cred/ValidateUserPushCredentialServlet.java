package es.caib.seycon.idp.ui.cred;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.PushAuthenticationService;
import com.soffid.iam.addons.federation.service.UserCredentialService;
import com.soffid.iam.api.System;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;

public class ValidateUserPushCredentialServlet extends BaseForm {
	static Log log = LogFactory.getLog(ValidateUserPushCredentialServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/validatePush"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	JSONObject o = new JSONObject();
    	o.put("done", false);
    	try {
	    	AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	    	if (ctx != null && ctx.getPushChallenge() != null) {
	    		for (UserCredentialChallenge ac: ctx.getPushChallenge())
	    			if (new RemoteServiceLocator().getPushAuthenticationService().isPushAuthenticationAccepted(ac))
	    				o.put("done", true);
	    	}
	    	byte b[] = o.toString().getBytes(StandardCharsets.UTF_8);
	    	resp.setContentType("application/json");
	    	resp.setContentLength(b.length);
	    	resp.getOutputStream().write(b);
	    	resp.getOutputStream().close();
    	} catch (Exception e) {
    		log.warn("Error checking push authentication", e);
    	}
    }


	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
		String error = "";
		try {
        	User user = new RemoteServiceLocator().getServerService().getUserInfo(ctx.getUser(), IdpConfig.getConfig().getSystem().getName());
    		for (UserCredentialChallenge ac: ctx.getPushChallenge()) { 
    			if (new RemoteServiceLocator().getPushAuthenticationService().isPushAuthenticationAccepted(ac)) {
					System system = IdpConfig.getConfig().getSystem();
					List<UserAccount> accounts = new RemoteServiceLocator().getAccountService().findUsersAccounts(user.getUserName(), system.getName());
					if (accounts == null || accounts.isEmpty())
						error = "Unauthorized";
					else
					{
						UserAccount account = accounts.iterator().next();
	            		ctx.authenticated(account.getName(), "Z", resp);
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(account.getName(), getServletContext(),req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
	            			return;
	            		}
	            		else
	            		{
	            	        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
	            	        dispatcher.forward(req, resp);
	            	        return;
	            		}
					}
				}
			}
		} catch (Exception e ) {
			log.warn("Error validating push authentication", e);
			error = Messages.getString("UserPasswordAction.internal.error");
		}
		
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);

    }
    
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		super.service(req, resp);
	}

}
