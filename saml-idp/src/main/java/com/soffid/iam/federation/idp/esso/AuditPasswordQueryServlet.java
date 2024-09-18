package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Calendar;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.EssoService;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.service.UserService;
import com.soffid.iam.sync.ServerServiceLocator;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.UnknownUserException;

public class AuditPasswordQueryServlet extends HttpServlet {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	Logger log = Log.getLogger("AuditPasswordQueryServlet");
	
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String user = req.getParameter("user");
        String key = req.getParameter("key");
        String account = req.getParameter("account");
        String system = req.getParameter("system");
        String url = req.getParameter ("url");
        String app = req.getParameter ("application");

        BufferedWriter writer = new BufferedWriter (new OutputStreamWriter(resp.getOutputStream(),"UTF-8"));
        try {
        	EssoService ss = new RemoteServiceLocator().getEssoService();
	        if (ss.auditPasswordQuery(user, key, account, system, url, app, url)) {
	        	writer.write("OK");
	        } else {
	        	writer.write("ERROR|Invalid key");
	        	log.warn("Invalid key {} for user {}", key, user);
	        }
        } catch (Exception e) {
            log.warn("Error getting keys", e);
            writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        } finally {
        	writer.close ();
        }
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
    {
    	doGet(req, resp);
    }
}
