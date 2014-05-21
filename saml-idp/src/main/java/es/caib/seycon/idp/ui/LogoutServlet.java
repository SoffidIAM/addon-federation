package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class LogoutServlet extends HttpServlet {

    
    public static final String URI = "/logout.jsp"; //$NON-NLS-1$

    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
    	HttpSession session = req.getSession(false);
    	if (session != null)
    		session.invalidate();
        HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
        try {
			g.generate(resp, "logout.html"); //$NON-NLS-1$
		} catch (TextFormatException e) {
			throw new ServletException(e);
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
