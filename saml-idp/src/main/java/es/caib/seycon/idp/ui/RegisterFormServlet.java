package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.federation.common.FederationMember;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class RegisterFormServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/registerForm"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    String emptyfy (Object obj)
    {
    	if (obj == null)
    		return "";
    	else
    		return obj.toString();
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        super.doGet(req, resp);

        AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
        if (! amf.allowUserPassword())
            throw new ServletException (Messages.getString("UserPasswordFormServlet.methodNotAllowed")); //$NON-NLS-1$

        try {
        	
        	IdpConfig config = IdpConfig.getConfig();
        	
        	FederationMember ip = amf.getIdentityProvider();
        	if (ip == null || ! ip.isAllowRegister() || ip.getUserTypeToRegister() == null)
        		throw new ServletException ("Not authorized to self register");
        	
            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            Map<String,String> args = (Map<String, String>) req.getAttribute("register");
            if (args != null) {
	            for (String arg: args.keySet()) {
	            	g.addArgument("previous_"+arg, emptyfy( args.get(arg))); //$NON-NLS-1$ //$NON-NLS-2$
	            	
	            }
            }
	        g.addArgument("refreshUrl", URI); //$NON-NLS-1$
            g.addArgument("registerUrl", RegisterAction.URI);
            g.addArgument("loginPage", UserPasswordFormServlet.URI);
            
        	ServerService serverService = new RemoteServiceLocator().getServerService();
        	LogonService logonService = new RemoteServiceLocator().getLogonService();
        	String userType = ip.getUserTypeToRegister();
        	g.addArgument("policy", 
        			config.getFederationService().getPolicyDescriptionForUserType(userType, IdpConfig.getConfig().getSystem().getName()));

            g.generate(resp, "registerPage.html"); //$NON-NLS-1$

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
