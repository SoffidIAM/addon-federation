package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;

import com.soffid.iam.sync.engine.kerberos.KerberosManager;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
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
        
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowKerberos())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$
        
//        final KerberosManager km = new KerberosManager();
        String principal = req.getRemoteUser();
        if (principal == null)
        {
        	resp.sendRedirect(UserPasswordFormServlet.URI);
        	return;
        }
        int split = principal.indexOf('@');
        if (split < 0)
        {
        	resp.sendRedirect(UserPasswordFormServlet.URI);
        	return;
        }
        String user = principal.substring(0, split);
        String domain = principal.substring(split + 1).toUpperCase();

    	String error = "";
    	try {
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	
	    	IdpConfig c = IdpConfig.getConfig();
	        final Challenge challenge = logonService.requestChallenge(Challenge.TYPE_KERBEROS, 
					principal,
					null,
					c.getHostName(),
					req.getRemoteAddr(),
					3);
	
	        challenge.setKerberosDomain(domain);
	
	        Sessio s = logonService.responseChallenge(challenge);  

	        for (UserAccount account: serverService.getUserAccounts(challenge.getUser().getId(), c.getSystem().getName()))
	        {
	        	if (!account.isDisabled())
	        	{
            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            		ctx.authenticated(account.getName(), "K");
            		ctx.store(req);
            		if ( ctx.isFinished())
            		{
            			new Autenticator().autenticate2(account.getName(), getServletContext(), req, resp, ctx.getUsedMethod(), false);
            			return;
            		}
	                return;
	        	}
	        }
            error = String.format(Messages.getString("PasswordChangeRequiredAction.unknown.user"), principal); //$NON-NLS-1$
    	} catch (Exception e) {
            error = Messages.getString("UserPasswordAction.internal.error")+e.toString(); //$NON-NLS-1$
            e.printStackTrace();
    	}
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }

}
