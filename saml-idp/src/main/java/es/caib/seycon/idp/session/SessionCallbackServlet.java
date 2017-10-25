package es.caib.seycon.idp.session;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SessionCallbackServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/Soffid.sso"; //$NON-NLS-1$


    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String id = req.getParameter("id");
    	if (id != null && SessionListener.isSessionAlive(id))
    		resp.getOutputStream().println("OK");
    	else
    		resp.getOutputStream().println("NO");
    }
    

}
