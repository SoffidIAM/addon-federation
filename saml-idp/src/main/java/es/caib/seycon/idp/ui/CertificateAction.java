package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.AuthnContext;

import es.caib.seycon.ng.exception.UnknownUserException;
import es.caib.seycon.idp.server.Autenticator;
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
	            } else {
	            	try {
	            		new Autenticator().autenticate(certUser, req, resp, AuthnContext.TLS_CLIENT_AUTHN_CTX, true);
	            		return;
	            	} catch (Exception e) {
	            		req.setAttribute("ERROR", e.toString()); //$NON-NLS-1$
	            	}
	            }
	        }
        } catch (InternalErrorException e) {
    		req.setAttribute("ERROR", e.getMessage()); //$NON-NLS-1$
        } catch (UnknownUserException e) {
    		req.setAttribute("ERROR", e.toString()); //$NON-NLS-1$
        }
       	RequestDispatcher dispatcher = req.getRequestDispatcher(amf.allowUserPassword() ?
       			UserPasswordFormServlet.URI: CertificateForm.URI);
        dispatcher.forward(req, resp);
    }
    
   

}
