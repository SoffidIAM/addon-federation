package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.activation.MimetypesFileTypeMap;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeaders;
import org.eclipse.jetty.http.HttpMethods;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.server.HttpConnection;
import org.eclipse.jetty.util.ByteArrayISO8859Writer;

import edu.internet2.middleware.shibboleth.common.profile.AbstractErrorHandler;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class ErrorServlet extends HttpServlet {

    public static final String URI = "/error.jsp";

	@Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String error = null;
        Throwable t = (Throwable) req
                .getAttribute(AbstractErrorHandler.ERROR_KEY);
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
        resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
        g.addArgument("ERROR", error);
        try {
			g.generate(resp, "errorPage.html");
		} catch (TextFormatException e) {
			e.printStackTrace();
		}
    }

}
