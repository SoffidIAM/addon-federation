package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import es.caib.seycon.ng.comu.lang.MessageFactory;


public class BaseForm extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private void process (HttpServletRequest req, HttpServletResponse resp) {
        if (req.getParameter("lang") != null) //$NON-NLS-1$
        {
            req.getSession().setAttribute("lang", req.getParameter("lang")); //$NON-NLS-1$ //$NON-NLS-2$
            MessageFactory.setThreadLocale(new Locale(req.getParameter("lang")));
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        process (req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        process (req, resp);
    }
    
}
