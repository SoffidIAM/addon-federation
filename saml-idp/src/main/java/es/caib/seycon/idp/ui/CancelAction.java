package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;

public class CancelAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/cancelAction"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	doPost(req, resp);
    }
    
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
    	if (authCtx == null)
       		getServletContext().getRequestDispatcher(LogoutServlet.URI).forward(req, resp);
    	
    	if (authCtx.getUser() != null) {
    		authCtx.setUser(null);
    		try {
				authCtx.initialize(req);
			} catch (																															Exception e) {
				new AuthenticationContext().store(req);
			}
       		getServletContext().getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
    		
    	} else {
	    	HttpSession session = req.getSession();
	    	OpenIdRequest r = (OpenIdRequest) session.getAttribute(SessionConstants.OPENID_REQUEST);
	    	
	    	if (r != null )
	    	{
	    		LogoutServlet.expireSession(req);
	    		resp.sendRedirect(r.getRedirectUrl() + (r.getRedirectUrl().contains("?") ? "&": "?") +"error=access_denied&error_description="+
	    				URLEncoder.encode("Access denied by user" , "UTF-8")+
	    				(r.getState() != null ? "&state="+r.getState(): ""));
	    	}
	    	else
	       		getServletContext().getRequestDispatcher(LogoutServlet.URI).forward(req, resp);
	
    	}
    }

}
