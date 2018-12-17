package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import es.caib.seycon.idp.textformatter.TextFormatException;

public class PasswordChangedForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/protected/passwordChanged"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HttpSession session = req.getSession();
            
            String user = (String) session.getAttribute(SessionConstants.SEU_USER); //$NON-NLS-1$
            if (user == null) {
                throw new ServletException("Expired session"); //$NON-NLS-1$
            }
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("return", (String) session.getAttribute("changepass-return-url")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("passwordChangeUrl", PasswordChangeAction.URI);
            g.generate(resp, "protected/passwordChanged.html"); //$NON-NLS-1$
            session.removeAttribute("changepass-return-url");
        } catch (TextFormatException e) {
            throw new ServletException(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
