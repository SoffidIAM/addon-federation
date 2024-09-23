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

import com.soffid.iam.addons.federation.service.EssoService;
import com.soffid.iam.api.Session;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.utils.Security;

public class CreateSessionServlet extends HttpServlet {

    Logger log = Log.getLogger("CreateSessionServlet");
    
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String user = req.getParameter("user");
        String clientIP = req.getParameter("clientIP");
        String port = req.getParameter("port");
        resp.setContentType("text/plain; charset=UTF-8");
        BufferedWriter writer = new BufferedWriter (new OutputStreamWriter(resp.getOutputStream(),"UTF-8"));
        try {
        	EssoService xs = new RemoteServiceLocator().getEssoService();
        	Session session = xs.createDummySession(user, Security.getClientIp(), clientIP, port);
            writer.write("OK|");
            writer.write(Long.toString(session.getId()));
            writer.write("\n");
        } catch (Exception e) {
            writer.write(e.getClass().getName() + "|" + e.getMessage()+"\n");
        }
        writer.close ();
    }

}
