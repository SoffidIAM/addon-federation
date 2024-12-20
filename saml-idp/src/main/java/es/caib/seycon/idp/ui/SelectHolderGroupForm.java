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
import es.caib.seycon.idp.server.AuthenticationContext;

public class SelectHolderGroupForm extends BaseForm {

	public static final String URI = "/holderGroupForm"; //$NON-NLS-1$
	private static final long serialVersionUID = 1L;
    private ServletContext context = null;
    Log log = LogFactory.getLog(getClass());

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	log.info(">>> HOLDERGROUP - SelectHolderGroupForm.doGet");
        super.doGet(req, resp);
        try {
        	log.info(">>> HOLDERGROUP - SelectHolderGroupForm.doGet, authenticating");
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

            g.addArgument("title", Messages.getString("selectHolderGroup")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("selectHolderGroupUrl", SelectHolderGroupAction.URI); //$NON-NLS-1$

            log.info("SelectHolderGroupForm.doGet - Se procede a consultar los holder groups...");
            Collection<GroupUser> gul = new RemoteServiceLocator().getGroupService().findUsersGroupByUserName(authCtx.getCurrentUser().getUserName());
            log.info("SelectHolderGroupForm.doGet - Se han encontrado "+((gul!=null) ? gul.size():0)+" holder groups");

            String error = (String) req.getAttribute("ERROR");
            if (gul==null || gul.isEmpty()) {
            	String message = Messages.getString("SelectHolderGroupForm.userWithoutHolderGroups");
            	if (error==null || error.trim().isEmpty()) {
            		error = message;
            	} else {
            		error = error+". "+message;
            	}
            }
            g.addArgument("ERROR", error);

            StringBuffer sb = new StringBuffer();
        	FederationService fs = IdpConfig.getConfig().getFederationService();
        	for (GroupUser gu : gul) {
        		Group group = new RemoteServiceLocator().getGroupService().findGroupByGroupName(gu.getGroup());
        		if (group.getType()!=null && fs.isOUTypeAHolderGroup(group.getType())) {
		        	sb.append("<div>");
		        	sb.append("<input type=\"radio\" name=\"holderGroup\" id=\"g"+group.getId()+"\" value=\""+group.getId()+"\" style=\"margin:7px\">");
		        	sb.append("<label for=\"g"+group.getId()+"\">"+group.getName()+" - "+group.getDescription()+"</label>");
		        	sb.append("</div>");
        		}
        	}
            g.addArgument("holderGroup", sb.toString()); //$NON-NLS-1$

            g.generate(resp, "selectHolderGroupPage.html"); //$NON-NLS-1$

        } catch (Exception e) {
        	log.info("SelectHolderGroupForm.doGet - Error genérico: "+e.getMessage());
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
