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

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.rememberPassword.PasswordRememberForm;
import es.caib.seycon.ng.exception.InternalErrorException;

public class PasswordRecoveryAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/passwordRecoveryAction"; //$NON-NLS-1$

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
	        
	    	String relyingParty = (String) session.
	                getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
	
	    	FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

	    	if (! ip.isAllowRecover())
	    		throw new InternalErrorException ("Registration is not permited");
	    	
	        String email = req.getParameter("email"); //$NON-NLS-1$
	        
    		String url = "https://"+config.getHostName()+":"+config.getStandardPort()+PasswordRecoveryAction2.URI;
    		
    		try
    		{
    			Class cl = Class.forName("com.soffid.iam.addons.rememberPassword.service.RememberPasswordUserService");
	            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordRememberForm.URI);
	            session.setAttribute("rememberPasswordEmail", email);
	            session.setAttribute("rememberPasswordChallenge", null);
	            dispatcher.forward(req, resp);
    		} 
    		catch (ClassNotFoundException e )
    		{
	      		config.getFederationService().sendRecoverEmail(email, 
	      				ip.getMailHost(), ip.getMailSenderAddress(), 
	      				url, ip.getOrganization());
	      		
	            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordRecoveryForm.URI);
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
