package es.caib.seycon.idp.ui.cred;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.System;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.remote.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;
import es.caib.seycon.ng.exception.SoffidStackTrace;

/**
 * Expects https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAssertionResponse
 * 
 * @author gbuades
 *
 */
public class ValidateCredential extends HttpServlet {
	public static final String URI = "/validateCredential"; //$NON-NLS-1$
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserCredential())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

		String clientJSON = req.getParameter("clientJSON");
		String authData = req.getParameter("authenticatorData");
		String signature = req.getParameter("signature");
		String rawId = req.getParameter("rawId");
		String serial = req.getParameter("serial");
		String error = null;
		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
		if (clientJSON == null)
		{
			error = "Missing clientJSON parameter";
		}  
		else if (authData == null)
		{
			error = "Missing attestation parameter";
		}
		else if (signature == null)
		{
			error = "Missing signature parameter";
		}
		else if (rawId == null)
		{
			error = "Missing rawId parameter";
		}
		else if (ctx.getUser() == null)
		{
			error = "Missing user name";
		}
		else
		{
			try {
            	User user = new RemoteServiceLocator().getServerService().getUserInfo(ctx.getUser(), IdpConfig.getConfig().getSystem().getName());
				UserCredential uc = null;
				for (UserCredential uc2: IdpConfig.getConfig().getUserCredentialService().findUserCredentials(user.getUserName())) {
					if (uc2.getType() == UserCredentialType.FIDO && 
							uc2.getRawid().equals(rawId)) {
						uc = uc2;
						break;
					}
				}
				if (uc == null)
				{
					error = "Cannot find token";
					req.getSession().setAttribute("serialCredentialToRemove", serial);
				}
				else if ( ! uc.getRawid().equals(rawId))
					error = String.format("Token id mismatch serial %s should have id %s", serial, rawId);
				else
				{
					WebCredentialParser p = new WebCredentialParser();
					p.setPublicKey(uc.getKey());
					String challenge = (String) req.getSession().getAttribute("fingerprintChallenge");
					byte[] challengeBinary = Base64.getDecoder().decode(challenge);
					p.parseAuthentication(clientJSON, authData, challengeBinary, signature, true);
					
					System system = IdpConfig.getConfig().getSystem();
					List<UserAccount> accounts = new RemoteServiceLocator().getAccountService().findUsersAccounts(user.getUserName(), system.getName());
					if (accounts == null || accounts.isEmpty())
						error = "Unauthorized";
					else
					{
						UserAccount account = accounts.iterator().next();
	            		ctx.authenticated(account.getName(), "F", resp);
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(account.getName(), getServletContext(),req, resp, ctx.getUsedMethod(), false);
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
			} catch (Exception e ) {
				log.warn("Error validating web authn ", e);
				error = Messages.getString("UserPasswordAction.internal.error");
			}
		}
		
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);

	}


}
