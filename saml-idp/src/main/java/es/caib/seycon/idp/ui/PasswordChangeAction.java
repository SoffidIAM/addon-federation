package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.api.Password;

import es.caib.seycon.BadPasswordException;
import es.caib.seycon.InvalidPasswordException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.ng.exception.UnknownUserException;

public class PasswordChangeAction extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/protected/passwordChangeAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	resp.addHeader("Cache-Control", "no-cache"); //$NON-NLS-1$ //$NON-NLS-2$
        HttpSession session = req.getSession();
        String user = (String) session.getAttribute(SessionConstants.SEU_USER); //$NON-NLS-1$
        if (user == null ) {
            throw new ServletException(Messages.getString("PasswordChangeAction.2")); //$NON-NLS-1$
        }

        String p1 = req.getParameter("j_password1"); //$NON-NLS-1$
        String p2 = req.getParameter("j_password2"); //$NON-NLS-1$
        String error = null;
        if (p1 == null || p1.length() == 0) {
            error = Messages.getString("PasswordChangeAction.7"); //$NON-NLS-1$
        } else if (p2 == null || p2.length() == 0) {
            error = Messages.getString("PasswordChangeAction.8"); //$NON-NLS-1$
        } else if (! p1.equals(p2)) {
            error = Messages.getString("PasswordChangeAction.9"); //$NON-NLS-1$
        } else {
       
            PasswordManager pm = new PasswordManager();
            try {
                pm.changePassword(user, new Password(p1));
                error = null;
            } catch (UnknownUserException e) {
                error = String.format(Messages.getString("PasswordChangeAction.10"), user); //$NON-NLS-1$
            } catch (InvalidPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeAction.11"), user); //$NON-NLS-1$
            } catch (BadPasswordException e) {
                error = String.format(Messages.getString("PasswordChangeAction.12")); //$NON-NLS-1$
            } catch (Exception e) {
                error = Messages.getString("PasswordChangeAction.13"); //$NON-NLS-1$
                LogFactory.getLog(getClass()).info("Error changing password", e);
            }
        }

        if (error != null) {
            req.setAttribute("ERROR", error); //$NON-NLS-1$
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangeForm.URI);
            dispatcher.forward(req, resp);
        } else {
            RequestDispatcher dispatcher = req.getRequestDispatcher(PasswordChangedForm.URI);
            dispatcher.forward(req, resp);
        }
    }

}
