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

import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.ng.exception.UnknownUserException;

public class ChangeSecretServlet extends HttpServlet {

	public ChangeSecretServlet ()
	{

	}
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("ChangeSecretServlet"); //$NON-NLS-1$
    
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {

    	
        String ssoAttribute = req.getParameter("sso"); //$NON-NLS-1$
        String user = req.getParameter("user"); //$NON-NLS-1$
        log.info("Processing change secret for {}", user, null);
        String key = req.getParameter("key"); //$NON-NLS-1$
        String secret = req.getParameter("secret"); //$NON-NLS-1$
        String description = req.getParameter("description"); //$NON-NLS-1$
        String account = req.getParameter("account"); //$NON-NLS-1$
        String system = req.getParameter("system"); //$NON-NLS-1$
        String value = req.getParameter("value"); //$NON-NLS-1$
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                        "UTF-8")); //$NON-NLS-1$
        
        User usuari;
		try {
			usuari = new RemoteServiceLocator().getUserService().findUserByUserName(user);
			if (usuari == null)
				throw new UnknownUserException(user);
			String result = new RemoteServiceLocator().getEssoService()
				.doChangeSecret(key, user, secret, account, system, ssoAttribute, description, value);
            writer.write(result);
	        writer.close();
		} catch (Exception e) {
			log.warn("Error getting keys", e); //$NON-NLS-1$
			writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n"); //$NON-NLS-1$ //$NON-NLS-2$
		}
        writer.close();

    }

}
