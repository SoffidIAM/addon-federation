package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnContext;

import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.exception.InternalErrorException;

public class CertificateAction extends HttpServlet {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost(req, resp);
	}

	public static final String URI = "/certificateLoginAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        try {
	        if (! amf.allowTls())
	    		req.setAttribute("ERROR", Messages.getString("CertificateAction.not_allowed")); //$NON-NLS-1$
	        else
	        {
	            CertificateValidator v = new CertificateValidator();
	            String certUser = v.validate(req);
	            if (certUser == null) {
	        		req.setAttribute("ERROR", Messages.getString("CertificateAction.1")); //$NON-NLS-1$ //$NON-NLS-2$
            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            		if (ctx != null)
            			ctx.authenticationFailure( ctx.getUser() );
	            } else {
	            	try {
	            		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	            		ctx.authenticated(certUser, "C", resp);
	            		ctx.store(req);
	            		if ( ctx.isFinished())
	            		{
	            			new Autenticator().autenticate2(certUser, getServletContext(),req, resp, ctx.getUsedMethod(), true);
	            			return;
	            		}
	            	} catch (Exception e) {
	        			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
	                    LogFactory.getLog(getClass()).info("Error validating certificate ", e);
	            	}
	            }
	        }
        } catch (InternalErrorException e) {
			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
            LogFactory.getLog(getClass()).info("Error validating certificate ", e);
        } catch (UnknownUserException e) {
			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
            LogFactory.getLog(getClass()).info("Error validating certificate ", e);
        }
       	RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }
    
   

}
