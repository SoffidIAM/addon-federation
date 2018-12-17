package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;

public class PasswordChangeForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/protected/passwordChange"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HttpSession session = req.getSession();
            
            if (req.getParameter("return") != null)
            {
            	session.setAttribute("changepass-return-url", req.getParameter("return"));
            }
            String user = (String) session.getAttribute(SessionConstants.SEU_USER); //$NON-NLS-1$
            if (user == null) {
                throw new ServletException(Messages.getString("PasswordChangeForm.expired.session")); //$NON-NLS-1$
            }
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("passwordChangeUrl", PasswordChangeAction.URI); //$NON-NLS-1$
            
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	
        	g.addArgument("policy", logonService.getPasswordPolicy(user, IdpConfig.getConfig().getSystem().getName()));

            g.generate(resp, "protected/passwordChange.html"); //$NON-NLS-1$
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
