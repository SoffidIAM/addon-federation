package es.caib.seycon.idp.cas;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.AllowedScope;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.LoginServlet;
import es.caib.seycon.idp.ui.LogoutServlet;
import es.caib.seycon.idp.ui.SessionConstants;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LogoutEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		String service = req.getParameter("service");
		try {
			IdpConfig config = IdpConfig.getConfig();

			if (service != null) {
				for ( FederationMember fm: config.getFederationService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "S")) {
					if (fm.getServiceProviderType() == ServiceProviderType.CAS) {
						if (fm.getOpenidLogoutUrl() != null) {
							for (String url: fm.getOpenidLogoutUrl()) {
								if (service.startsWith(url) && !url.trim().isEmpty()) {
									req.getSession().setAttribute("$$soffid$$-logout-redirect", service);
								}
							}
						}
					}
				}
			}
			resp.sendRedirect(LogoutServlet.URI);
		} catch (Exception e) {
			throw new ServletException("Error parsing request paramenters", e);
		}
    	
	}
}
