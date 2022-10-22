package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collections;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class RootServlet extends LangSupportServlet {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/"; //$NON-NLS-1$
	Log log = LogFactory.getLog(getClass());
	
    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
    	resp.sendRedirect("/protected/");
    }
}
