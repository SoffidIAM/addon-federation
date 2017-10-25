package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.util.storage.StorageService;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry;
import edu.internet2.middleware.shibboleth.idp.profile.IdPProfileHandlerManager;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

public class RegisteredFormServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/registeredForm"; //$NON-NLS-1$
    private ServletContext context;
    private IdPProfileHandlerManager handlerManager;
    private SessionManager<Session> sessionManager;
    private StorageService<String, LoginContextEntry> storageService;
    private RelyingPartyConfigurationManager relyingPartyConfigurationManager;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
        handlerManager = HttpServletHelper.getProfileHandlerManager(context);
        sessionManager = HttpServletHelper.getSessionManager(context);
        storageService = (StorageService<String, LoginContextEntry>) HttpServletHelper.getStorageService(context);
        relyingPartyConfigurationManager = HttpServletHelper.getRelyingPartyConfigurationManager(context);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$

        try {
        	
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("refreshUrl", URI); //$NON-NLS-1$

            g.generate(resp, "registeredPage.html"); //$NON-NLS-1$

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
