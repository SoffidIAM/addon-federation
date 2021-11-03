package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class LogoutServlet extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/logout.jsp"; //$NON-NLS-1$

    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
    	expireSession(req);
        HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
        try {
			g.generate(resp, "logout.html"); //$NON-NLS-1$
		} catch (TextFormatException e) {
			throw new ServletException(e);
		}
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
			        			new es.caib.seycon.ng.addons.federation.remote.RemoteServiceLocator()
			        				.getFederationService()
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
