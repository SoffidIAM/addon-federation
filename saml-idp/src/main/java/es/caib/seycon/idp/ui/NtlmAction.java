package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.sync.engine.kerberos.KerberosManager;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.comu.Challenge;
import es.caib.seycon.ng.comu.Sessio;
import es.caib.seycon.ng.comu.UserAccount;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class NtlmAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/ntlmLoginAction"; //$NON-NLS-1$

    protected void doGet (HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
    {
    	doPost (req, resp);
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        
        String principal = req.getRemoteUser();
        if (principal == null)
        {
        	req.getSession().setAttribute("disableKerberos", Boolean.TRUE);
        	req.setAttribute("ERROR", Messages.getString("KerberosLogin.noToken")); //$NON-NLS-1$
        	resp.sendRedirect(UserPasswordFormServlet.URI);
        	return;
        }
        int split = principal.indexOf('@');
        if (split < 0)
        {
        	req.getSession().setAttribute("disableKerberos", Boolean.TRUE);
        	req.setAttribute("ERROR", Messages.getString("KerberosLogin.noToken")); //$NON-NLS-1$
        	resp.sendRedirect(UserPasswordFormServlet.URI);
        	return;
        }
        String user = principal;
        String system = principal.substring(split + 1);

    	String error = "";
    	try {
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	
    		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
    		if (ctx != null) {
		    	IdpConfig c = IdpConfig.getConfig();
		        final Challenge challenge = logonService.requestChallenge(Challenge.TYPE_KERBEROS,
						user,
						system,
						c.getHostName(),
						ctx.getHostId(resp),
						3);
		
	//	        challenge.setKerberosDomain(domain);
		
		        Sessio s = logonService.responseChallenge(challenge);  
	
		        for (UserAccount account: serverService.getUserAccounts(challenge.getUser().getId(), c.getSystem().getName()))
		        {
		        	if (!account.isDisabled())
		        	{
	            		ctx.authenticated(account.getName(), "K", resp);
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(account.getName(), getServletContext(), req, resp, ctx.getUsedMethod(), false, ctx.getHostId(resp));
	            			return;
	            		}
		                return;
		        	}
		        }
	    		if (ctx != null)
	    			ctx.authenticationFailure(ctx.getUser(), Messages.getString("PasswordChangeRequiredAction.unknown.user"));
	            error = String.format(Messages.getString("PasswordChangeRequiredAction.unknown.user"), principal); //$NON-NLS-1$
    		}
    	} catch (Exception e) {
            error = Messages.getString("UserPasswordAction.internal.error"); //$NON-NLS-1$
            LogFactory.getLog(getClass()).info("Error validating kerberos token ", e);
    	}
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
    	req.getSession().setAttribute("disableKerberos", Boolean.TRUE);
        dispatcher.forward(req, resp);
    }

}
