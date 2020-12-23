package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class ConsentFormServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/consentForm"; //$NON-NLS-1$
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
        super.doGet(req, resp);

        try {
        	HttpSession session = req.getSession();
        	
            String method = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
            if (session.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM) == null)
            	session.setAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM, method);
            else
            	method = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.AUTHN_METHOD_PARAM);
            
            String entityId = (String) req.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);
            if (entityId != null)
            	session.setAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM, entityId);
            else
            	entityId = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM); 

        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
        	if (authCtx == null )
        	{
        		throw new ServletException("URL not valid at this time");
        	}

        	IdpConfig config = IdpConfig.getConfig();

        	String user = authCtx.getCurrentUser().getUserName();
        	String authMethod = authCtx.getUsedMethod();
        	String serviceProvider = authCtx.getPublicId();
        	
        	StringBuffer sb = new StringBuffer();
        	
        	sb.append("<ul>");
        	for (String attribute: new UserAttributesGenerator().generateAttributeNames(getServletContext(), user, authMethod, serviceProvider))
        	{
        		sb.append("<li>")
        			.append(attribute.replace("&", "&amp;").replace("'", "&apos;") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                            .replace("\"", "&quot;").replace("<", "&lt;") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
                            .replace(">", "&gt;")
                            .replace("\n", "<BR>"))
        			.append("</li>");
        	}
        	sb.append("</ul>");

            HtmlGenerator g = new HtmlGenerator(context, req);
            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("serviceProvider", emptyfy( serviceProvider )); //$NON-NLS-1$ //$NON-NLS-2$
            g.addArgument("attributes", sb.toString()); //$NON-NLS-1$ //$NON-NLS-2$

	        g.addArgument("consentUrl", ConsentAction.URI); //$NON-NLS-1$
            
            g.generate(resp, "consentPage.html"); //$NON-NLS-1$

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
