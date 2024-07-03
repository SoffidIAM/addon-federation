package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;
import com.soffid.iam.addons.passrecover.common.UserAnswer;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserService;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserServiceBase;
import com.soffid.iam.api.Password;

import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.addons.passrecover.remote.RemoteServiceLocator;

public class PasswordRecoveryModuleAction extends HttpServlet {
	static Log log = LogFactory.getLog(UserPasswordFormServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/passwordRecoveryPluginAction"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            if (ctx == null || ctx.getCurrentUser() == null || ctx.getRecoverChallenge() == null)
            {
            	resp.sendRedirect(UserPasswordFormServlet.URI);
            	return;
            }
        	RecoverPasswordUserService svc = (RecoverPasswordUserService) 
        			new RemoteServiceLocator()
        				.getRemoteService(RecoverPasswordUserService.REMOTE_PATH);
        	RecoverPasswordChallenge challenge = ctx.getRecoverChallenge();
        	
        	int i = 0;
        	for (UserAnswer answer: challenge.getQuestions()) {
        		answer.setAnswer(req.getParameter("q_"+i));
        		i++;
        	}
        	if (svc.responseChallenge(challenge)) {
        		challenge.setAnswered(true);
        		HttpSession s = req.getSession();
                s.setAttribute(SessionConstants.SEU_TEMP_USER, null);
                s.setAttribute(SessionConstants.SEU_TEMP_PASSWORD, null);
                s.setAttribute(SessionConstants.TITLE_RECOVER, "true");
                RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeRequiredForm.URI);
                dispatcher.forward(req, resp);
        	} else {
				ctx.authenticationFailure(ctx.getUser(), "Error recovering password");
        		req.setAttribute("ERROR", Messages.getString("accessDenied"));
        		req.getServletContext().getRequestDispatcher(PasswordRecoveryModuleForm.URI)
        			.forward(req, resp);
        	}
        } catch (Exception e) {
        	log.warn("Error recovering password", e);
        	req.setAttribute("ERROR", e.getMessage());
    		req.getServletContext().getRequestDispatcher(PasswordRecoveryModuleForm.URI)
			.forward(req, resp);
		}
    }

	private String escape(String question) {
		return question
				.replace("&", "&amp;")
				.replace("<", "&lt;")
				.replace(">", "&gt;");
	}
}
