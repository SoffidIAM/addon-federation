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

public class IframeSession extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/iframe-session"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.generate(resp, "iframe-session.html"); //$NON-NLS-1$
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
