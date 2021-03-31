package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.User;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;

public class PasswordRecoveryAction2 extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/recover"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        String error = null;
        try  {
	    	IdpConfig config = IdpConfig.getConfig();
	    	
	    	HttpSession session = req.getSession();
	        
	    	String relyingParty = req.getParameter("rp");
	
	    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

	    	if (! ip.isAllowRecover())
	    		throw new InternalErrorException ("Recovery is not permited");
	    	
	        String key = req.getParameter("key"); //$NON-NLS-1$
	        
    		String url = "https://"+config.getHostName()+":"+config.getStandardPort()+PasswordRecoveryForm.URI;

      		User usuari = config.getFederationService().verifyRecoverEmail(key);
      		
      		if (usuari == null)
      		{
      			req.setAttribute("ERROR", "This password has already been recovered.");
				RequestDispatcher dispatcher = req.getRequestDispatcher(ErrorServlet.URI);
		        dispatcher.forward(req, resp);
      			
      		} else {
                HttpSession s = req.getSession();
                
                s.setAttribute(SessionConstants.SEU_TEMP_USER, usuari.getUserName());

                RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
		        dispatcher.forward(req, resp);
      		}
			return;
        } catch (Exception e) {
			error = Messages.getString("UserPasswordAction.internal.error");
            LogFactory.getLog(getClass()).info("Error recovering password ", e);
        }

       
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(ErrorServlet.URI);
        dispatcher.forward(req, resp);
    }

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		doPost(req, resp);
	}

    
}
