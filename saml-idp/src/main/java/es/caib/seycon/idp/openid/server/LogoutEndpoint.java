package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.Session;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.LogoutHandler;
import es.caib.seycon.idp.server.LogoutResponse;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.LogoutServlet;
import es.caib.seycon.idp.ui.SessionConstants;

public class LogoutEndpoint extends HttpServlet {
	Log log = LogFactory.getLog(getClass());
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
		log.info(">>> LOGOUT - id_token_hint="+tokenHint);
		log.info(">>> LOGOUT - post_logout_redirect_uri="+postLogoutRedirectUri);
		log.info(">>> LOGOUT - logout_hint="+logoutHint);
		log.info(">>> LOGOUT - client_id="+clientId);
		log.info(">>> LOGOUT - state="+state);
		try {
			if (OidcDebugController.isDebug()) {
				log.info("Received logout request");
				log.info("id_token_hint            = "+tokenHint);
				log.info("logout_hint              = "+logoutHint);
				log.info("client_id                = "+clientId);
				log.info("post_logout_redirect_uri = "+postLogoutRedirectUri);
				log.info("state                    = "+state);
			}
			IdpConfig config = IdpConfig.getConfig();

			LogoutResponse response = null;
			
			// Identify the response URL
			String logoutUrl = LogoutServlet.URI;
			if (tokenHint != null) {
				TokenHandler th = new TokenHandler();
				log.info(">>> LOGOUT - getToken");
				TokenInfo t = th.getToken(tokenHint);
				if (t != null) {
					log.info(">>> LOGOUT - tokenInfo encontrado");
					new TokenHandler().revoke(getServletContext(), req, t);
					log.info(">>> LOGOUT - revocacion de la sesion");
					if (clientId == null) {
						clientId = t.getRequest().getFederationMember().getOpenidClientId();
						log.info(">>> LOGOUT - clientId="+clientId);
					}
				}
			}
			if (clientId != null && postLogoutRedirectUri != null) {
				FederationMember fm = new RemoteServiceLocator().getFederacioService().findFederationMemberByClientID(clientId);
				if (fm != null) {
					if (validateResponseUrl(postLogoutRedirectUri, fm)) {
						if (postLogoutRedirectUri.startsWith("BASE64")) {
							postLogoutRedirectUri = new String(Base64.getDecoder().decode(postLogoutRedirectUri.substring(6)));
							log.info(">>> LOGOUT - postLogoutRedirectUri decodificada: "+postLogoutRedirectUri);
						}
						if (state != null) {
							if (postLogoutRedirectUri.contains("?"))
								postLogoutRedirectUri += "&state=";
							else
								postLogoutRedirectUri += "?state=";
							postLogoutRedirectUri += URLEncoder.encode(state, "UTF-8");
						}
						logoutUrl = postLogoutRedirectUri;
						log.info(">>> LOGOUT - URL para redireccion: "+logoutUrl);
					}
				} else {
					log.info(">>> LOGOUT - clientId no encontrado como service provider");
				}
			}
			
			Session session = new Autenticator().getSession(req, false);
			if (session != null) {
				response = new LogoutHandler().logout(getServletContext(), req, session, true);
				log.info(">>> LOGOUT - hay sesion, se redirige a LogoutHandler");
			}
			if (response != null && response.getFrontRequests().isEmpty()) {
				resp.sendRedirect(logoutUrl);
				log.info(">>> LOGOUT - Redireccion (1)");
			} else {
				if (! logoutUrl.equals(LogoutServlet.URI)) {
					req.getSession().setAttribute("$$soffid$$-logout-redirect", logoutUrl);
					log.info(">>> LOGOUT - Redireccion en sesion");
				}
				resp.sendRedirect(LogoutServlet.URI);
				log.info(">>> LOGOUT - Redireccion (2)");
			}
	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
	}

	private boolean validateResponseUrl(String postLogoutRedirectUri, FederationMember fm) {
		if (postLogoutRedirectUri.startsWith("BASE64")) {
			log.info(">>> LOGOUT - URL en base64, es una redirección interna");
			return true;
		}
		boolean ok = false;
		for (String url: fm.getOpenidLogoutUrl()) {
    		if (postLogoutRedirectUri.equals(url) || postLogoutRedirectUri.startsWith(url+"?")) {
    			ok = true;
    			log.info(">>> LOGOUT - postLogoutRedirectUri encontrada en el service provider (1)");
    		}
    		if (url.endsWith("*") && postLogoutRedirectUri.startsWith(url.substring(0, url.length()-1))) {
    			ok = true;
    			log.info(">>> LOGOUT - postLogoutRedirectUri encontrada en el service provider (2)");
			}
		}
		if (!ok)
			log.info(">>> LOGOUT - postLogoutRedirectUri "+postLogoutRedirectUri+" no encontrada en el service provider");
		return ok;
	}

}
