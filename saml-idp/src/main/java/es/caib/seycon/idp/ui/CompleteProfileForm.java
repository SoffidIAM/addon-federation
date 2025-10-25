package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.GroupUser;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;

public class CompleteProfileForm extends BaseForm {

	public static final String URI = "/completeProfileForm"; //$NON-NLS-1$
	private static final long serialVersionUID = 1L;
    private ServletContext context = null;
    Log log = LogFactory.getLog(getClass());

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        super.doGet(req, resp);
        try {
        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
        	if (authCtx==null)
        		throw new ServletException("URL not valid at this time");

        	String user = authCtx.getCurrentUser().getUserName();
        	String account = authCtx.getUser();
        	String authMethod = authCtx.getUsedMethod();
        	String serviceProvider = authCtx.getPublicId();

            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("user", user); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("account", account); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("authMethod", authMethod); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("serviceProvider", emptyfy( serviceProvider )); //$NON-NLS-1$ //$NON-NLS-2$

            g.addArgument("progressiveProfileUrl", ProgressiveProfileAction.URI); //$NON-NLS-1$

            Collection<GroupUser> gul = new RemoteServiceLocator().getGroupService().findUsersGroupByUserName(authCtx.getCurrentUser().getUserName());

            String error = (String) req.getAttribute("ERROR");
            g.addArgument("ERROR", error);
            g.addArgument("form", authCtx.getProgressiveProfile().getForm());
            g.generate(resp, "progressiveProfile.html"); //$NON-NLS-1$

        } catch (Exception e) {
        	log.info("SelectHolderGroupForm.doGet - Error generico: "+e.getMessage());
            throw new ServletException(e);
		}
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }

    private String emptyfy (Object obj)
    {
    	if (obj == null)
    		return "";
    	else
    		return obj.toString();
    }
}
