package es.caib.seycon.idp.ui.openid;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.openid.consumer.OpenidConsumer;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;

public class OpenIdRequestAction extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/openIdRequest"; //$NON-NLS-1$

    void generateError (HttpServletRequest req, HttpServletResponse resp, String msg) throws ServletException, IOException
    { 
    	req.setAttribute ("ERROR", msg);
    	req.getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String id = req.getParameter("j_username");
        process(req, resp, id);
    }

	private void process(HttpServletRequest req, HttpServletResponse resp,
			String id) throws ServletException, IOException {
		HttpSession session = req.getSession();
        resp.addHeader("Cache-Control", "no-cache"); //$NON-NLS-1$ //$NON-NLS-2$

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        FederationMember ip;
		try {
			ip = amf.getIdentityProvider();
        
	        if (ip == null)
	        {
	        	generateError(req, resp, "Unable to guess identity provider");
	        	return ;
	        }
	        
	        OpenidConsumer consumer = new OpenidConsumer(ip);
	        
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
        process(req, resp, id);
    }

}
