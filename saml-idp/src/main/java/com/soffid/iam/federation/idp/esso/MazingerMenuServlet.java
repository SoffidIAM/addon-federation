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

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.EssoService;
import com.soffid.iam.api.AccessTree;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.service.AuthorizationService;
import com.soffid.iam.service.EntryPointService;
import com.soffid.iam.service.NetworkService;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.service.UserService;
import com.soffid.iam.sync.ServerServiceLocator;
import com.soffid.iam.sync.engine.db.ConnectionPool;
import com.soffid.iam.sync.engine.session.SessionManager;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownHostException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class MazingerMenuServlet extends HttpServlet {
    Logger log = Log.getLogger("MazingerMenuServlet");
    public MazingerMenuServlet() {
    }

    ConnectionPool pool = ConnectionPool.getPool();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {
        resp.setContentType("text/plain; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String user = req.getParameter("user");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        SessionManager mgr = SessionManager.getSessionManager();
        String key = req.getParameter("key");
        try {
            User usuari = new RemoteServiceLocator().getUserService().findUserByUserName(user);
            if (usuari == null) {
                throw new UnknownUserException(user);
            }
            Session foundSessio = null;
            for (Session s: new RemoteServiceLocator().getSessionService().getActiveSessions(usuari.getId())) {
                if (key.equals (s.getKey()))
                {
                    foundSessio = s;
                    break;
                }
            }
            if (foundSessio == null) {
                throw new InternalErrorException("Invalid session key");
            }
            log.info("Generating menus for {}", user, null);
            StringBuffer buffer = new StringBuffer();
            EssoService essos = new RemoteServiceLocator().getEssoService();
            AccessTree root = essos.findRootAccessTree(user);
            generatePuntEntrada(root, buffer, essos, user);
            writer.write("OK|");
            writer.write(buffer.toString());
        } catch (Exception e) {
            log("Error getting menu", e);
            writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        }
        writer.close();
    }
    
    private String removeSlash(String s)
    {
    	return s.replace('/', ' ').replace('\\',' ').replace('|',' ');
    }

    public void generatePuntEntrada(AccessTree punt, StringBuffer buffer, EssoService essos, String user) throws InternalErrorException {

        if (punt.isMenu()) {
            buffer.append("MENU|");
            buffer.append(removeSlash(punt.getName()));
            buffer.append("|");
            for (AccessTree child : essos.findChildren(user, punt)) {
                generatePuntEntrada(child, buffer, essos, user);
            }
            buffer.append("ENDMENU|");
        } else if (!punt.getExecutions().isEmpty()) {
            buffer.append(punt.getId());
            buffer.append("|");
            buffer.append(removeSlash(punt.getName()));
            buffer.append("|");
            buffer.append(punt.getId() == null ? "-1" : punt.getId().toString());
            buffer.append("|");
        }

    }

}
