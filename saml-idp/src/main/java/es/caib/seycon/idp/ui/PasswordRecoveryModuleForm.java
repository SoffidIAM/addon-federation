package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;
import com.soffid.iam.addons.passrecover.common.UserAnswer;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserService;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserServiceBase;

import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.ng.addons.passrecover.remote.RemoteServiceLocator;

public class PasswordRecoveryModuleForm extends HttpServlet {
	static Log log = LogFactory.getLog(UserPasswordFormServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/passwordRecoveryPluginForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        try {
            AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
            if (ctx == null || ctx.getUser() == null)
            {
            	resp.sendRedirect(UserPasswordFormServlet.URI);
            	return;
            }
        	HtmlGenerator g = new HtmlGenerator(context, req);
        	RecoverPasswordUserService svc = (RecoverPasswordUserService) 
        			new RemoteServiceLocator()
        				.getRemoteService(RecoverPasswordUserService.REMOTE_PATH);
        	ctx.fetchUserData();
        	RecoverPasswordChallenge challenge = svc.requestChallenge(ctx.getCurrentUser().getUserName());
        	g.addArgument("RecoverURL", PasswordRecoveryModuleAction.URI);
        	g.addArgument("BackURL", UserPasswordFormServlet.URI);
        	g.addArgument("ERROR", (String) req.getAttribute("ERROR"));
        	ctx.setRecoverChallenge(challenge);
        	StringBuffer sb = new StringBuffer();
        	int i = 0;
        	for (UserAnswer answer: challenge.getQuestions()) {
        		sb.append("<p><span class='labeltextbox'><span class='label'>")
        			.append(escape(answer.getQuestion()))
        			.append(":</span><input autofocus type='text' ")
        			.append("name='q_").append(i++).append("' style='width: 8em'/>")
        			.append("</span></p>");
        	}
        	g.addArgument("recoverBlock", sb.toString());
        	g.generate(resp, "recoverPage.html"); //$NON-NLS-1$
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

	private String escape(String question) {
		return question
				.replace("&", "&amp;")
				.replace("<", "&lt;")
				.replace(">", "&gt;");
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		doGet(req, resp);
	}
}
