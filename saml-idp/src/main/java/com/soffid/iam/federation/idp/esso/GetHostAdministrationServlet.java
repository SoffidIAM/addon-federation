package com.soffid.iam.federation.idp.esso;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.HeuristicMixedException;
import javax.transaction.HeuristicRollbackException;
import javax.transaction.NotSupportedException;
import javax.transaction.RollbackException;
import javax.transaction.SystemException;

import org.mortbay.log.Log;
import org.mortbay.log.Logger;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.sync.engine.db.ConnectionPool;
import com.soffid.iam.sync.service.LogonService;
import com.soffid.iam.sync.web.Messages;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownHostException;

public class GetHostAdministrationServlet extends HttpServlet
{

    private static final long serialVersionUID = 1L;
    Logger log = Log.getLogger("GetHostAdministrationServlet"); //$NON-NLS-1$

    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
		throws ServletException, IOException
	{
        String hostIP = com.soffid.iam.utils.Security.getClientIp();
        String hostName = req.getParameter("host"); //$NON-NLS-1$
        String usuariPeticio = req.getParameter("user"); //$NON-NLS-1$
        String passPeticio = req.getParameter("pass"); //$NON-NLS-1$

        PasswordValidation validPassword = PasswordValidation.PASSWORD_WRONG;

        try
        {
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	validPassword = logonService.validatePassword(usuariPeticio, null, passPeticio);
        }
        catch (Throwable th)
        {
            validPassword = PasswordValidation.PASSWORD_WRONG;
        }

        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(resp.getOutputStream(),
                "UTF-8")); //$NON-NLS-1$

        if (validPassword == PasswordValidation.PASSWORD_GOOD)
        {
            try
            {
                log.info(String.format(
					"GetHostAdministrationServlet: Starting to obtain admin user-password from host '{}', user request '{}' from IP '%1$s'", 
						hostIP), hostName, usuariPeticio);

                // Verifiquem paràmeters
                if (hostName == null || (hostName != null && "".equals(hostName.trim())) //$NON-NLS-1$
                        || usuariPeticio == null
                        || (usuariPeticio != null && "".equals(usuariPeticio.trim()))) //$NON-NLS-1$
                    throw new Exception(Messages.getString("GetHostAdministrationServlet.IncorrectParamsMessage")); //$NON-NLS-1$

                String resultat = getHostAdministration(hostName, hostIP, usuariPeticio);
                writer.write("OK|" + resultat); //$NON-NLS-1$
                log.info(String.format(
    				"Admin user-password retrieved from host '{}', user request '{}' IP '%1$s'", 
    				hostIP), hostName, usuariPeticio);
            }
            catch (Exception e)
            {
                log.warn(String.format(
    				"GetHostAdministrationServlet: ERROR performing getHostAdministration at '{}', user request '{}' from IP '%1$s'", 
    				hostIP), hostName, usuariPeticio);
                log.warn("GetHostAdministrationServlet: Exception: ", e); 
                writer.write(e.getClass().getName() + "|" + e.getMessage() + "\n"); //$NON-NLS-1$ //$NON-NLS-2$
            }
        }
        else
        {
            log.warn(String.format(
				"GetHostAdministrationServlet: ERROR performing getHostAdministration at '{}', user request '{}' from IP '%1$s'", 
				hostIP), hostName, usuariPeticio);

            InternalErrorException uex = new InternalErrorException(Messages.getString("GetHostAdministrationServlet.IncorrectPasswordMessage")); //$NON-NLS-1$
            log.warn("GetHostAdministrationServlet: Exception: ", uex); 
            writer.write(uex.getClass().getName() + "|" + uex.getMessage() + "\n"); //$NON-NLS-1$ //$NON-NLS-2$
        }
        writer.close();
    }

    public String getHostAdministration(String hostname, String hostIP,
		String usuariPeticio) throws InternalErrorException, IOException,
		UnknownHostException, SystemException, RollbackException,
		HeuristicMixedException, HeuristicRollbackException,
		NotSupportedException
	{    
        String userPass[] = new RemoteServiceLocator().getEssoService().getHostAdministration(hostname, hostIP, usuariPeticio);
        if (userPass[0] == null || userPass[1] == null)
        	throw new InternalErrorException(Messages.getString("GetHostAdministrationServlet.NoAdminAccountMessage")); //$NON-NLS-1$
        return userPass[0] + "|" + userPass[1]; //$NON-NLS-1$
    }
}
