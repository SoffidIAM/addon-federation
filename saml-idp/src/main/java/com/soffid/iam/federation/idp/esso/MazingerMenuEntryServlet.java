package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.sql.SQLException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.AccessTree;
import com.soffid.iam.api.AccessTreeExecution;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.sync.engine.db.ConnectionPool;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

public class MazingerMenuEntryServlet extends HttpServlet {
	public MazingerMenuEntryServlet() {
    }

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    ConnectionPool pool = ConnectionPool.getPool();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {
        resp.setContentType("text/plain; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String user = req.getParameter("user");
        String id = req.getParameter("id");
        String codi = req.getParameter("codi");
        String key = req.getParameter("key");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        
        try {
	        if (user == null) {
        		try {
        			getEntryPoint(null, id, codi, writer);
        		} catch (Exception e) {
        			log("Error getting menu id:" + id + " codi:" + codi, e);
        			writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        		}	        	
	        } else {
        	
        		try {
        			Session sessio = null;
        			User usuari = new RemoteServiceLocator().getUserService().findUserByUserName(user);
        			for (Session s: new RemoteServiceLocator().getSessionService().getActiveSessions(usuari.getId())) {
        				if (key.equals (s.getKey()))
        				{
        					sessio = s;
        					break;
        				}
        			}
        			if (sessio == null) {
        				throw new InternalErrorException("Invalid session key");
        			}
        			getEntryPoint(user, id, codi, writer);
        		} catch (Exception e) {
        			log("Error getting menu id:" + id + " codi:" + codi, e);
        			writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        		}
	        }
        } catch (Exception e1) {
        	throw new ServletException(e1);
        }
        writer.close();
    }

	public void getEntryPoint(String user, String id, String codi, BufferedWriter writer)
			throws InternalErrorException, IOException, SQLException {
		AccessTree pue = null;
		if (id != null)
			pue  = new RemoteServiceLocator().getEssoService().findApplicationAccessById(user, Long.decode(id).longValue());
		
		else if (codi != null) {
			Collection<AccessTree> punts = new RemoteServiceLocator().getEssoService().findApplicationAccessByCode(user, codi);
			if (punts.size() == 1)
				pue = punts.iterator().next();
		}
		if (pue == null)
			writer.write ("ERROR|Unknown application entry point");
		else
		{
			String result = generatePuntEntrada(pue, com.soffid.iam.utils.Security.getClientIp());
			writer.write("OK|");
			writer.write(result);
		}
	}

    public String generatePuntEntrada(AccessTree pue, String ip) throws InternalErrorException,
            SQLException, IOException {

        AccessTreeExecution exe = new RemoteServiceLocator().getEssoService().getExecution(pue, ip);

        if (exe == null)
        	throw new InternalErrorException("Unable to execute");
        else
            return exe.getExecutionTypeCode() + "|" + exe.getContent();
    }

}
