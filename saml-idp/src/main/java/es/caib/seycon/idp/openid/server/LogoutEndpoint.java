package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Session;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.LogoutHandler;
import es.caib.seycon.idp.server.LogoutResponse;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.LogoutServlet;
import es.caib.seycon.idp.ui.SessionConstants;

public class LogoutEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		String tokenHint = req.getParameter("id_token_hint");
		String logoutHint = req.getParameter("logout_hint");
		String clientId = req.getParameter("client_id");
		String postLogoutRedirectUri = req.getParameter("post_logout_redirect_uri");
		String state = req.getParameter("state");
		try {
			IdpConfig config = IdpConfig.getConfig();

			LogoutResponse response = null;
			
			// Identify the response URL
			String logoutUrl = LogoutServlet.URI;
			if (tokenHint != null) {
				TokenHandler th = new TokenHandler();
				TokenInfo t = th.getToken(tokenHint);
				if (t != null) {
					new TokenHandler().revoke(getServletContext(), req, t);
					if (clientId == null) {
						clientId = t.getRequest().getFederationMember().getOpenidClientId();
					}
				}
			}
			if (clientId != null && postLogoutRedirectUri != null) {
				FederationMember fm = new RemoteServiceLocator().getFederacioService().findFederationMemberByClientID(clientId);
				if (fm != null) {
					if (validateResponseUrl(postLogoutRedirectUri, fm)) {
						if (state != null) {
							if (postLogoutRedirectUri.contains("?"))
								postLogoutRedirectUri += "&state=";
							else
								postLogoutRedirectUri += "?state=";
							postLogoutRedirectUri += URLEncoder.encode(state, "UTF-8");
						}
						logoutUrl = postLogoutRedirectUri;
					}
				}
			}
			
			Session session = new Autenticator().getSession(req, false);
			if (session != null)
				response = new LogoutHandler().logout(getServletContext(), req, session, true);
			if (response != null && response.getFrontRequests().isEmpty()) {
				resp.sendRedirect(logoutUrl);
			} else {
				if (! logoutUrl.equals(LogoutServlet.URI))
					req.getSession().setAttribute("$$soffid$$-logout-redirect", logoutUrl);
				resp.sendRedirect(LogoutServlet.URI);
			}
	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
	}

	private boolean validateResponseUrl(String postLogoutRedirectUri, FederationMember fm) {
		boolean ok = false;
		for (String url: fm.getOpenidLogoutUrl()) {
    		if (postLogoutRedirectUri.equals(url) || postLogoutRedirectUri.startsWith(url+"?")) 
    			ok = true;
    		if (url.endsWith("*") && postLogoutRedirectUri.startsWith(url.substring(0, url.length()-1))) 
    			ok = true;
		}
		return ok;
	}

}
