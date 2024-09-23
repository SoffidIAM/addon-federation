package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.LogonService;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class PasswordChangeRequiredForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/passwordChangeRequired"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HttpSession session = req.getSession();
            
            String uri = PasswordChangeRequiredAction.URI;
            String user = (String) session.getAttribute(SessionConstants.SEU_TEMP_USER);
            if (user == null) {
            	AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            	if (ctx != null && ctx.getCurrentUser() != null &&
            			ctx.getRecoverChallenge() != null &&
            			ctx.getRecoverChallenge().isAnswered()) {
            		user = ctx.getCurrentUser().getUserName();
            		uri = PasswordRecoveryModuleAction2.URI;
            	}
            }
            if (user == null) {
                throw new ServletException(Messages.getString("PasswordChangeRequiredForm.expired.session")); //$NON-NLS-1$
            }
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("user", user);
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("passwordChangeLoginUrl", uri); //$NON-NLS-1$
            
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	
        	
        	g.addArgument("policy", logonService.getPasswordPolicy(user, IdpConfig.getConfig().getSystem().getName()));

        	String isTitleRecover = (String) session.getAttribute(SessionConstants.TITLE_RECOVER);
        	if (isTitleRecover!=null && "true".equals(isTitleRecover)) {
        		g.addArgument("isFromRecoveryPassword", "true");
        	} else {
        		g.addArgument("isFromResetPassword", "true");
        	}

            g.generate(resp, "passwordChangeRequired.html"); //$NON-NLS-1$
        } catch (TextFormatException e) {
            throw new ServletException(e);
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
