package es.caib.seycon.idp.ui.oauth;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.oauth.consumer.FacebookConsumer;
import es.caib.seycon.idp.oauth.consumer.GoogleConsumer;
import es.caib.seycon.idp.oauth.consumer.LinkedinConsumer;
import es.caib.seycon.idp.oauth.consumer.OAuth2Consumer;
import es.caib.seycon.idp.oauth.consumer.OpenidConnectConsumer;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;

public class OauthRequestAction extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/oauthRequest"; //$NON-NLS-1$

    void generateError (HttpServletRequest req, HttpServletResponse resp, String msg) throws ServletException, IOException
    { 
    	req.setAttribute ("ERROR", msg);
    	req.getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String id = req.getParameter("id");
    	if (id == null)
    		id = req.getParameter("idp");
        process(req, resp, id);
    }

	private void process(HttpServletRequest req, HttpServletResponse resp,
			String id) throws ServletException, IOException {
		HttpSession session = req.getSession();
		String user = req.getParameter("user");
        resp.addHeader("Cache-Control", "no-cache"); //$NON-NLS-1$ //$NON-NLS-2$

		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        if (! ctx.getNextFactor().contains("E"))
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        FederationMember ip;
		try {
			ip = ctx.getIdentityProvider();
        
	        if (ip == null)
	        {
	        	generateError(req, resp, "Unable to guess identity provider");
	        	return ;
	        }
	        
	        if (id == null)
	        {
	        	generateError(req, resp, "Missing id parameter");
	        	return;
	        }
	        
	        FederacioService fs = new RemoteServiceLocator().getFederacioService();
	        OAuth2Consumer consumer = null;
	        for (FederationMember fm: fs.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, id, "I"))
	        {
	        	if (fm.getIdpType().equals(IdentityProviderType.FACEBOOK))
	        		consumer = new FacebookConsumer(fm);
	        	else if (fm.getIdpType().equals(IdentityProviderType.GOOGLE))
	        		consumer = new GoogleConsumer(fm);
	        	else if (fm.getIdpType().equals(IdentityProviderType.LINKEDIN))
	        		consumer = new LinkedinConsumer(fm);
	        	else if (fm.getIdpType().equals(IdentityProviderType.OPENID_CONNECT))
	        		consumer = new OpenidConnectConsumer(fm);
	        }
	        if (user != null) {
	        	user = IdpConfig.getConfig().getFederationService().getLoginHint(id, user);
	        	consumer.setRequestedUser(user);
	        }
	        
	        if (consumer == null)
	        {
	        	generateError(req, resp, String.format("Unable to find identity provider %s", id));
	        }
	        
	        consumer.store(session);
	        
	        consumer.authRequest(id, req, resp);

		} catch (Exception e) {
        	generateError(req, resp, String.format("Unable to contact identity provider: %s", e.toString()));
		}
	}


    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String id = req.getParameter("id");
    	if (id == null)
    		id = req.getParameter("idp");
        process(req, resp, id);
    }

}
