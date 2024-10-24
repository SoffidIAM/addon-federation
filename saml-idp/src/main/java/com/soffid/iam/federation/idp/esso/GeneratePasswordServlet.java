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

import com.soffid.iam.api.Account;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Session;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.SecretStoreService;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class GeneratePasswordServlet extends HttpServlet {

	public GeneratePasswordServlet ()
	{
	}
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("GetSecretsServlet");

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {

        String user = req.getParameter("user");
        String key = req.getParameter("key");
        String account = req.getParameter("account");
        String system = req.getParameter("system");
        String value = req.getParameter("value");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                        "UTF-8"));
        try {
            User usuari = new RemoteServiceLocator().getUserService().findUserByUserName(user);
            if (usuari == null)
                throw new UnknownUserException(user);

            for (Session sessio : new RemoteServiceLocator().getSessionService().getActiveSessions(usuari.getId())) {
                if (sessio.getKey().equals(key) ) {
                    writer.write(generatePassword(usuari, account, system));
                    writer.close();
                    return;
                }
            }
            writer.write("ERROR|Invalid key");
            log.warn("Invalid key {} for user {}", key, user);
        } catch (Exception e) {
            log.warn("Error getting keys", e);
            writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n");
        }
        writer.close();

    }

    /**
	 * @param usuari.getCodi()
	 * @param secret
	 * @param account
	 * @param system
     * @return
     * @throws InternalErrorException 
     * @throws IOException 
	 */
	private String generatePassword (User usuari, String account,
					String system) throws InternalErrorException, IOException
	{
        SecretStoreService sss = new RemoteServiceLocator().getSecretStoreService();
        if (system != null && account != null)
        {
        	Account acc = new RemoteServiceLocator().getAccountService().findAccount(account, system);
        	
        	if (acc instanceof UserAccount)
        	{
        		if (! ((UserAccount) acc).getUser().equals(usuari.getUserName()))
        			return "ERROR|Not authorized";
        	}
        	else
        	{
        		boolean found = false;
        		for (Account acc2: new RemoteServiceLocator().getAccountService().getUserGrantedAccounts(usuari))
        		{
        			if (acc2.getId().equals(acc.getId()))
        			{
        				found = true;
        				break;
        			}
        		}
        		if (! found)
        			return "ERROR|Not authorized";
        	}
        	Password password = new RemoteServiceLocator().getServerService()
        			.generateFakePassword(account, system);
            return "OK|"+password.getPassword();
        } else {
        	return "ERROR|Missing arguments";
        }
    }

}
