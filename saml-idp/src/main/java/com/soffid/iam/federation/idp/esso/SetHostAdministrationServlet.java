package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.api.Host;
import com.soffid.iam.api.Password;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.service.NetworkService;
import com.soffid.iam.sync.engine.db.ConnectionPool;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.ConfigurationCache;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SetHostAdministrationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("SetHostAdministrationServlet");

    public SetHostAdministrationServlet() {
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {

        String hostIP = com.soffid.iam.utils.Security.getClientIp();

        String hostName = req.getParameter("host");
        String adminUser = req.getParameter("user");
        String adminPass = req.getParameter("pass");
        String serial = req.getParameter("serial");

        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        try {
            // Verifiquem paràmeters
            if (hostName == null || (hostName != null && "".equals(hostName.trim()))
                    || adminUser == null || (adminUser != null && "".equals(adminUser.trim()))
                    || adminPass == null || (adminPass != null && "".equals(adminPass.trim())))
                throw new Exception("Incorrect parameters");

            setHostAdministration(serial, hostName, hostIP, adminUser, adminPass);
            writer.write("OK|" + hostName);
        } catch (Exception e) {
            log.warn(
                    "SetHostAdministrationServlet: ERROR performing setHostAdministration on host {} for user {} from IP address "
                            + hostIP, hostName, adminUser);
            writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        }
        writer.close();

    }

    HashMap<String,Date> lastChange = new HashMap<String,Date>();
    public void setHostAdministration(String serial, String hostname, String hostIP,
            String adminUser, String adminPass) throws InternalErrorException, SQLException, IOException {
        Host maq = new RemoteServiceLocator().getEssoService().findHostBySerialNumber(serial);
        if (maq != null) {
            synchronized (lastChange) {
	            Date last = lastChange.get(hostname);
	            if (last != null && System.currentTimeMillis() - last.getTime() < 3600000) // A change each hour
	            {
	            	log.warn("Password change storm from {}", hostname, null);
	                throw new InternalErrorException("IncorrectHostException");
	            }
	            lastChange.put(hostname, new Date());
            }
            // Si la comprovació de ip-nomhost ha anat bé, fem
            // l'actualització del usuari-passwd
            new RemoteServiceLocator().getEssoService().setHostAdministration(serial, adminUser, new Password(adminPass));

        } else {
            throw new InternalErrorException("Host not found " + hostname);
        }

    }

}
