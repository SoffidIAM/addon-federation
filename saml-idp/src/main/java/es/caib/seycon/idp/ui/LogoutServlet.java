package es.caib.seycon.idp.ui;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.api.Session;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.FrontLogoutRequest;
import es.caib.seycon.idp.server.LogoutHandler;
import es.caib.seycon.idp.server.LogoutResponse;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LogoutServlet extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/logout.jsp"; //$NON-NLS-1$

    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
        HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
        try {
        	boolean close = false;
        	String desiredTarget = (String) req.getSession().getAttribute("$$soffid$$-logout-redirect");
        	g.addArgument("logoutList", "[]");
        	Session session = new Autenticator().getSession(req, false);
        	if (session == null) {
    			close = true;
        	}
        	else if (isSafeLogout(req)) {
        		LogoutResponse r = new LogoutHandler().logout(getServletContext(), req, session, true);
        		if (r.getFrontRequests() != null && ! r.getFrontRequests().isEmpty()) {
        			JSONArray a = new JSONArray();
        			for ( FrontLogoutRequest fr: r.getFrontRequests()) {
        				JSONObject o = new JSONObject();
        				o.put("name", fr.getDescription());
        				o.put("url", fr.getUrl());
        				a.put(o);
        			}
                	g.addArgument("logoutList", a.toString());
                	g.addArgument("showProgress", "true");
            		new LogoutHandler().logout(getServletContext(), req, session, false);
        		} else {
        			close = true;
        		}
        	}
        	else 
        	{
        		List<FederationMemberSession> sessions = countSessions(session);
        		if (sessions.isEmpty()) {
            		new LogoutHandler().logout(getServletContext(), req, session, false);
        			close = true;
        		}
        		else
        		{
        			g.addArgument("showLogout", "true");
        			g.addArgument("Close_n_sessions", String.format(g.getResourceBundle().getString("Close_n_sessions"), sessions.size()));
        			StringBuffer sb = new StringBuffer();
        			for (FederationMemberSession s: sessions) {
        				FederationMember fm = IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(s.getFederationMember());
        				if (fm != null)
        					sb.append(fm.getName()).append("\n");
        			}
        			g.addArgument("open_sessions", sb.toString());
        		}
        	}
        	if (close) {
        		g.addArgument("showClose", "true");
        		req.getSession().invalidate();
        		if (desiredTarget != null)
        		{
        			resp.sendRedirect(desiredTarget);
        			return;
        		}
        	}
       		g.generate(resp, "logout.html"); //$NON-NLS-1$
		} catch (Exception e) {
            String error = Messages.getString("UserPasswordAction.internal.error"); //$NON-NLS-1$
            g.addArgument("error", error);
            LogFactory.getLog(getClass()).info("Error closing sessions ", e);
			try {
				g.generate(resp, "logout.html");
			} catch (TextFormatException | IOException e1) {
				throw new ServletException("Error generating logout page", e1);
			} //$NON-NLS-1$
		}
    }

	private List<FederationMemberSession> countSessions(Session session) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
		return IdpConfig.getConfig().getFederationService().findFederationMemberSessions(session.getId());
	}

	private boolean isSafeLogout(HttpServletRequest req) throws URISyntaxException {
		if (! "logout".equals(req.getParameter("action")))
			return false;
		String referer = req.getHeader("Referer");
		String host = req.getHeader("Host");
		if (host != null && host.contains(":"))
			host = host.substring(0, host.indexOf(":"));
		java.net.URI refererUri = new java.net.URI(referer);
		if (refererUri.getHost().equals(host) &&
				(refererUri.getPath().equals(URI) || refererUri.getPath().startsWith(URI+"?")))
			return true;
		else
			return false;
	}

	public static void expireSession(HttpServletRequest req) {
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

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        process (req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        process (req, resp);
    }

}
