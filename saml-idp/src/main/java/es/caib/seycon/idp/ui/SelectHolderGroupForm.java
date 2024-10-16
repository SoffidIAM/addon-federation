package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.api.Group;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.server.AuthenticationContext;

public class SelectHolderGroupForm extends BaseForm {

	public static final String URI = "/holderGroupForm"; //$NON-NLS-1$
	private static final long serialVersionUID = 1L;
    private ServletContext context = null;

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
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("user", user); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("account", account); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("authMethod", authMethod); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("serviceProvider", emptyfy( serviceProvider )); //$NON-NLS-1$ //$NON-NLS-2$

            g.addArgument("title", Messages.getString("selectHolderGroup")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("selectHolderGroupUrl", SelectHolderGroupAction.URI); //$NON-NLS-1$

            Collection<Group> lg = new RemoteServiceLocator().getUserService().getUserGroups(authCtx.getCurrentUser().getId());
        	StringBuffer sb = new StringBuffer();
        	for (Group group : lg) {
        		if (group.getType()!=null) {
		        	sb.append("<div>");
		        	sb.append("<input type=\"radio\" name=\"holderGroup\" id=\"g"+group.getId()+"\" value=\""+group.getId()+"\" style=\"margin:7px\">");
		        	sb.append("<label for=\"g"+group.getId()+"\">"+group.getName()+" - "+group.getDescription()+"</label>");
		        	sb.append("</div>");
        		}
        	}
            g.addArgument("holderGroup", sb.toString()); //$NON-NLS-1$

            g.generate(resp, "selectHolderGroupPage.html"); //$NON-NLS-1$

        } catch (Exception e) {
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
