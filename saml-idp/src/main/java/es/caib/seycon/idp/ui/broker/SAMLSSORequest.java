package es.caib.seycon.idp.ui.broker;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.SamlRequest;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.ui.AuthenticationMethodFilter;
import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.idp.ui.UserPasswordFormServlet;

public class SAMLSSORequest extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/sp-profile/SAML2/Forward"; //$NON-NLS-1$
    private ServletContext context;
    Log log = LogFactory.getLog(getClass());
    
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
    	String user = req.getParameter("user");
    	String idp = req.getParameter("idp");

		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
        if (! ctx.getNextFactor().contains("E"))
            throw new ServletException ("Authentication method not allowed"); //$NON-NLS-1$

        try {

	    	IdpConfig cfg = IdpConfig.getConfig();
			FederacioService federacioService = new RemoteServiceLocator().getFederacioService();
			
			Long timeOut = cfg.getFederationMember().getSessionTimeout();
			SamlRequest samlRequest = federacioService.generateSamlRequest( cfg.getPublicId(),
					idp,
					user,
					timeOut == null ? 30*60: timeOut.longValue());
			if (samlRequest.getMethod().equals( "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") )
			{
				resp.setContentType("text/html; charset=UTF-8");
				StringBuffer sb = new StringBuffer();
				sb.append("<html><body onLoad='document.forms[0].submit();'><form method='post' action='")
					.append(encode(samlRequest.getUrl()))
					.append("'>")
					.append("<input name='RelayState' type='hidden' value='")
					.append(encode(samlRequest.getParameters().get("RelayState")))
					.append("'/>")
					.append("<input name='SAMLRequest' type='hidden' value='")
					.append(encode(samlRequest.getParameters().get("SAMLRequest")))
					.append("'/>")
					.append("<input type='submit' value='Forwarding ....'/>")
					.append("</form>")
					.append("</body></html>");
				ServletOutputStream out = resp.getOutputStream();
				out.write(sb.toString().getBytes("UTF-8"));
				out.close();
			}
			else
			{
				resp.setContentType("text/html; charset=UTF-8");
				StringBuffer sb = new StringBuffer();
				sb.append(samlRequest.getUrl())
					.append("?RelayState=")
					.append(URLEncoder.encode(samlRequest.getParameters().get("RelayState"),"UTF-8"))
					.append("&SAMLRequest=")
					.append(URLEncoder.encode(samlRequest.getParameters().get("SAMLRequest"),"UTF-8"));
				resp.sendRedirect(sb.toString());
			}
		} catch (Exception e) {
			LogFactory.getLog(getClass()).warn("Error forwarding to external IdP", e);
			req.setAttribute("ERROR", Messages.getString("UserPasswordAction.internal.error"));
		    RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
		    dispatcher.forward(req, resp);
		}
    }

	private String encode(String url) {
		return url.replaceAll("\"", "\\\\\"");
	}
    

}
