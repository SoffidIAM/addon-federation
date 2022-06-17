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

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
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
			doLogout(req, resp);
			req.getSession().invalidate();
			
			IdpConfig config = IdpConfig.getConfig();
		
			if (clientId != null && postLogoutRedirectUri != null) {
				FederationMember fm = new RemoteServiceLocator().getFederacioService().findFederationMemberByClientID(clientId);
				if (fm != null) {
					if (fm.getOpenidLogoutUrl().contains(postLogoutRedirectUri)); {
						if (state != null) {
							if (postLogoutRedirectUri.contains("?"))
								postLogoutRedirectUri += "&state=";
							else
								postLogoutRedirectUri += "?state=";
							postLogoutRedirectUri += URLEncoder.encode(state, "UTF-8");
						}
						resp.sendRedirect(postLogoutRedirectUri);
						return;
					}
				}
			} else if (postLogoutRedirectUri != null) {
				resp.sendRedirect(postLogoutRedirectUri);
				return;
			}
			resp.sendRedirect(LogoutServlet.URI);
	    	
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
	}

	private void doLogout(HttpServletRequest req, HttpServletResponse resp) {
		HttpSession session = req.getSession(false);
    	if (session != null) 
    	{
            try 
            {
            	session.removeAttribute("Soffid-Authentication-Context");

				IdpConfig config = IdpConfig.getConfig();
				
				String relyingParty = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
				
				FederationMember ip = null;
				if (relyingParty != null)
				{
					ip = config.findIdentityProviderForRelyingParty(relyingParty);
				} 
				if (ip == null)
					ip = config.getFederationMember();
				
			    if (ip != null) {
			        if (ip.getSsoCookieName() != null && ip.getSsoCookieName().length() > 0)
			        {
			        	for (Cookie c: req.getCookies())
			        	{
			        		if (c.getName().equals(ip.getSsoCookieName()))
			        		{
			        			new RemoteServiceLocator()
			        				.getFederacioService()
			        				.expireSessionCookie(c.getValue());
			        		}
			        	}
			        }
			    }
			} catch (Exception e) {
				LogFactory.getLog(LogoutServlet.class).warn("Error expiring session", e);
			}		
        
    		session.invalidate();
    	}
	}

}