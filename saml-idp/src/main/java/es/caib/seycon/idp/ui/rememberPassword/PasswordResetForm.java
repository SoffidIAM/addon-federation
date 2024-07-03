package es.caib.seycon.idp.ui.rememberPassword;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.passrecover.common.RecoverPasswordChallenge;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.HtmlGenerator;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.comu.UserAccount;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class PasswordResetForm extends BaseForm {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    public static final String URI = "/rememberPasswordForm2"; //$NON-NLS-1$

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            super.doGet(req, resp);
            HttpSession session = req.getSession();
            
            RecoverPasswordChallenge challenge = (RecoverPasswordChallenge) session.getAttribute("rememberPasswordChallenge");

            if (challenge == null) {
                throw new ServletException(Messages.getString("PasswordChangeRequiredForm.expired.session")); //$NON-NLS-1$
            }
            HtmlGenerator g = new HtmlGenerator(getServletContext(), req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("passwordChangeLoginUrl", PasswordResetAction.URI); //$NON-NLS-1$
            
        	String server = (String) session.getAttribute("recoverServer");
        	if (server == null)
        	{
        		server = ServerLocator.getInstance().getServer();
        		session.setAttribute("recoverServer", server);
        	}
        	RemoteServiceLocator rsl = new RemoteServiceLocator(server);
        	ServerService serverService = rsl.getServerService();
        	LogonService logonService = rsl.getLogonService();
        	
        	String dispatcher = IdpConfig.getConfig().getSystem().getName();
        	Usuari usuari = serverService.getUserInfo(challenge.getUser(), null);
        	Collection<UserAccount> accounts = serverService.getUserAccounts(usuari.getId(), dispatcher);
        	if (accounts.isEmpty())
        	{
        		g.addArgument("policy", "");
        		g.addArgument("user", usuari.getCodi());
        		session.setAttribute("account", usuari.getCodi());
        	}
        	else
        	{
        		UserAccount acc = accounts.iterator().next();	
        		session.setAttribute("account", acc.getName());
        		g.addArgument("policy", logonService.getPasswordPolicy(acc.getName(), acc.getDispatcher()));
        		g.addArgument("user", acc.getName());
        	}

        	String isTitleRecover = (String) session.getAttribute(SessionConstants.TITLE_RECOVER);
        	if (isTitleRecover!=null && "true".equals(isTitleRecover)) {
        		g.addArgument("isFromRecoveryPassword", "true");
        	} else {
        		g.addArgument("isFromResetPassword", "true");
        	}

        	g.generate(resp, "passwordChangeRequired.html"); //$NON-NLS-1$
        } catch (TextFormatException e) {
            throw new ServletException(e);
        } catch (Exception e) {
            throw new ServletException(e);
		}
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
