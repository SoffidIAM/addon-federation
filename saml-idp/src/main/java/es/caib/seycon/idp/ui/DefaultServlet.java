package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.MimetypesFileTypeMap;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import es.caib.seycon.idp.textformatter.TextFormatException;

public class DefaultServlet extends HttpServlet {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String [] mimes = { ".css", "text/css", ".png", "image/png", ".svg", "image/svg+xml"}; //$NON-NLS-1$ //$NON-NLS-2$
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	if (req.getPathInfo().equals("/"))
        	resp.sendRedirect("/protected/userinfo");

        String s = "web"+req.getPathInfo(); //$NON-NLS-1$
        InputStream in = DefaultServlet.class.getClassLoader().getParent().getResourceAsStream(s);
        if (in == null)
        	in = DefaultServlet.class.getClassLoader().getParent().getResourceAsStream(s);
        if (in == null)
        	in = DefaultServlet.class.getClassLoader().getResourceAsStream(s);
        if (in == null || s.endsWith("/")) {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.setContentType("text/html");
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", "HTTP/404 Page not found");
            try {
    			g.generate(resp, "errorPage.html");
    		} catch (TextFormatException e) {
    			e.printStackTrace();
    		}
        } else {
            resp.setStatus(HttpServletResponse.SC_OK);
            String mimeType =  MimetypesFileTypeMap.getDefaultFileTypeMap().getContentType(s);
            for (int i = 0; i < mimes.length; i+=2) {
                if (s.endsWith(mimes[i]))
                    mimeType = mimes[i+1];
            }
            resp.setContentType(mimeType);
            OutputStream out = resp.getOutputStream();
            byte b [] = new byte [4096];
            do {
                int read = in.read(b);
                if (read < 0)
                    break;
                out.write (b, 0, read);
            } while (true);
            out.close();
            in.close();
        }
    }
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}

}
