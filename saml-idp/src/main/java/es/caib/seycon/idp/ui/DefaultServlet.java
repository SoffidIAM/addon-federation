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

public class DefaultServlet extends HttpServlet {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static final String [] mimes = { ".css", "text/css", ".png", "image/png"}; //$NON-NLS-1$ //$NON-NLS-2$
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String s = "web"+req.getPathInfo(); //$NON-NLS-1$
        InputStream in = DefaultServlet.class.getClassLoader().getParent().getResourceAsStream(s);
        if (in == null)
        	in = DefaultServlet.class.getClassLoader().getParent().getResourceAsStream(s);
        if (in == null)
        	in = DefaultServlet.class.getClassLoader().getResourceAsStream(s);
        if (in == null) {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
            resp.setContentType("text/plain");
            ServletOutputStream out = resp.getOutputStream();
            out.write("HTTP/404 Not found".getBytes());
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

}
