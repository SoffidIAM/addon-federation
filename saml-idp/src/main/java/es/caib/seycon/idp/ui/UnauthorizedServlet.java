package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class UnauthorizedServlet extends BaseForm {
	static Log log = LogFactory.getLog(UnauthorizedServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/unauthorized"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String url = (String) req.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
    	if (url.equals("/esso/kerberosLogin"))
    		context.getRequestDispatcher("/esso/kerberosLogin").forward(req, resp);
    	else
    		context.getRequestDispatcher(UserPasswordFormServlet.URI).forward(req, resp);
    }
    

}
