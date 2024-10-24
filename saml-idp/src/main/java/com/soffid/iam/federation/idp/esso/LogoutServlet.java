package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.api.Session;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.service.SessionService;

public class LogoutServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("PasswordLoginServlet");
    
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        
        String session = req.getParameter("sessionId");
        BufferedWriter writer = new BufferedWriter (new OutputStreamWriter(resp.getOutputStream(),"UTF-8"));
        try {
            SessionService sessioService = new RemoteServiceLocator().getSessionService();
            Session sessio = sessioService.getSessionByHost(Long.decode(session), com.soffid.iam.utils.Security.getClientIp());
            if (sessio != null)
            	sessioService.destroySession(sessio);
        } catch (Exception e) {
            log.warn("Error performing logout", e);
            writer.write(e.getClass().getName() + "|" + e.getMessage()+"\n");
        }
        writer.close ();
        
    }

}
