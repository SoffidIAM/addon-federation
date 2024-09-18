package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.service.AuthorizationService;
import com.soffid.iam.service.NetworkService;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.service.UserService;
import com.soffid.iam.sync.engine.challenge.ChallengeStore;
import com.soffid.iam.utils.ConfigurationCache;
import com.soffid.iam.utils.Security;

public class KeepaliveSessionServlet extends HttpServlet {

    Logger log = Log.getLogger("KeepaliveSessionServlet");
    
    static public Map<String,String> newSessionKeys = new Hashtable<String, String>();

    public KeepaliveSessionServlet() {
    }
    
    private String computeDiferences(String key, String newKey) {
    	if (newKey == null)
    		return null;
        StringBuffer b = new StringBuffer();
        ChallengeStore s = ChallengeStore.getInstance();
        for (int i=0; i <key.length();i++)
        {
            char ch = key.charAt(i);
            char ch2 = newKey.charAt(i);
            int dif = s.charToInt(ch2) - s.charToInt(ch);
            b.append (s.intToChar(dif));
        }
        return b.toString();
    }

    
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/plain; charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String user = req.getParameter("user");
        String key = req.getParameter("key");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8"));
        String[] auths = null;
        try {
            Security.nestedLogin(user, new String [] { 
                Security.AUTO_HOST_ALL_QUERY+Security.AUTO_ALL
            });

            try {
                Session sessio = null;
				String newSessionKey = null;
                User usuari = new RemoteServiceLocator().getUserService().findUserByUserName(user);
                for (Session s: new RemoteServiceLocator().getSessionService().getActiveSessions(usuari.getId())) {
                    if (key.equals (s.getKey()))
                    {
                        sessio = s;
                        newSessionKey = computeDiferences(sessio.getKey(), sessio.getTemporaryKey());
                        break;
                    }
                }
                if (sessio == null) {
                	log ("User "+user+" trying to keep alive an expired session from "+com.soffid.iam.utils.Security.getClientIp());
                	writer.write("EXPIRED|Invalid session");
                }
                else
                {
                	new RemoteServiceLocator().getSessionService().sessionKeepAlive(sessio);
                	writer.write("OK|");
                	if (newSessionKey != null)
                	{
                		writer.write(newSessionKey+"|");
                	}
                }
            } catch (Exception e) {
                log("Error keeping alive session", e);
                writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
            } finally {
                Security.nestedLogoff();
            }
        } catch (Exception e1) {
            throw new ServletException(e1);
        }
        writer.close();
    }

}