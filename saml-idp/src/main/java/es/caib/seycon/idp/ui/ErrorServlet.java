package es.caib.seycon.idp.ui;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class ErrorServlet extends HttpServlet {
	Log log = LogFactory.getLog(getClass());
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/error.jsp";

	@Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String error = null;
        Throwable t = (Throwable) req
                .getAttribute(AbstractErrorHandler.ERROR_KEY);
        log.warn("Error generating page "+req.getRequestURL(), t);
        if (t != null)
        	error = t.toString();
        
        if (error == null)
        {
			Object e = req.getAttribute("javax.servlet.error.exception");
			if (e != null)
				error = e.toString();
        }
        
        if (error == null)
        {
        	error = (String) req.getAttribute("ERROR");
        }
        
        if (error == null)
        {
        	error = "Uknown error";
        }

        try {
            resp.reset();
        } catch (IllegalStateException e) {

        }
        Integer code = (Integer) req.getAttribute("javax.servlet.error.status_code");
        if (code == null)
        	code = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
        resp.setStatus(code.intValue());
        HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
        g.addArgument("ERROR", "HTTP/"+code);
        try {
			g.generate(resp, "errorPage.html");
		} catch (TextFormatException e) {
			e.printStackTrace();
		}
    }

}
