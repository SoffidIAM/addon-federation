package es.caib.seycon.idp.ui.rememberPassword;

import java.io.IOException;
import java.util.Iterator;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;
import com.soffid.iam.addons.passrecover.common.UserAnswer;
import com.soffid.iam.addons.passrecover.service.RecoverPasswordUserService;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.ErrorServlet;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;

public class PasswordRememberAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/passwordRememberAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        String error = null;
        try  {
	    	IdpConfig config = IdpConfig.getConfig();
	    	
	    	String answer = req.getParameter("answer");
	    	Integer question = Integer.decode(req.getParameter("questionid"));
	    	HttpSession session = req.getSession();
	    	
            RecoverPasswordChallenge challenge = (RecoverPasswordChallenge) session.getAttribute("rememberPasswordChallenge");

            int i = 0;
            Iterator<UserAnswer> it = challenge.getQuestions().iterator();
            UserAnswer ua = null;
            while ( i <= question.intValue())
            {
            	ua = it.next();
            	i ++;
            }
            
            ua.setAnswer(answer);
            if (it.hasNext())
            {
            	session.setAttribute("rememberPasswordQuestion", Integer.valueOf(question.intValue()+1));
	            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordRememberForm.URI);
	            dispatcher.forward(req, resp);
            }
            else
            {
            	String server = (String) session.getAttribute("recoverServer");
            	if (server == null)
            	{
            		server = ServerLocator.getInstance().getServer();
            		session.setAttribute("recoverServer", server);
            	}
            	RemoteServiceLocator rsl = new RemoteServiceLocator(server);
            	RecoverPasswordUserService rpus = (RecoverPasswordUserService) rsl.getRemoteService(RecoverPasswordUserService.REMOTE_PATH);
            	if (rpus.responseChallenge(challenge))
            	{
                    req.setAttribute("ERROR", "Invalid questions"); //$NON-NLS-1$
                	session.setAttribute("rememberPasswordQuestion", Integer.valueOf(0));
    	            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordResetForm.URI);
    	            dispatcher.forward(req, resp);
            	} else {
                    req.setAttribute("ERROR", "Invalid questions"); //$NON-NLS-1$
                	session.setAttribute("rememberPasswordQuestion", Integer.valueOf(0));
    	            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordRememberForm.URI);
    	            dispatcher.forward(req, resp);
            	}
            }
            return;
        } catch (InternalErrorException e) {
            error = "Unable to activate account: "+e.getMessage(); //$NON-NLS-1$
        } catch (Exception e) {
			error = Messages.getString("UserPasswordAction.internal.error");
            LogFactory.getLog(getClass()).info("Error activating account ", e);
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
