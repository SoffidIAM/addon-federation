package es.caib.seycon.idp.ui;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Cookie;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.SessionChecker;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.broker.SAMLSSORequest;
import es.caib.seycon.idp.ui.oauth.OauthRequestAction;
import es.caib.seycon.ng.exception.InternalErrorException;

public class UserAction extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

    public static final String URI = "/userNameAction"; //$NON-NLS-1$

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        SessionChecker checker = new SessionChecker();
        if (!checker.checkSession(req, resp))
        {
        	checker.generateErrorPage(req, resp);
        	return;
        }
        
        String u = req.getParameter("j_username"); //$NON-NLS-1$
        String error = Messages.getString("UserPasswordAction.wrong.password"); //$NON-NLS-1$
       
        if (u == null || u.length() == 0) {
            error = Messages.getString("UserPasswordAction.missing.user.name"); //$NON-NLS-1$
        } else {
        	String idp = null;
			try {
				idp = new RemoteServiceLocator().getFederacioService().searchIdpForUser(u);
			} catch (InternalErrorException | IOException e) {
				LogFactory.getLog(getClass()).warn("Error guessing identity provider for "+u, e);
			}
        	if (idp != null) {
        		RequestDispatcher d;
    			try {
	        		FederationMember data = new RemoteServiceLocator().getFederacioService().findFederationMemberByPublicId(idp);
	        		if ( data.getIdpType() == IdentityProviderType.SAML ||
	        				(data.getIdpType() == IdentityProviderType.SOFFID))
	        			d = req.getRequestDispatcher(SAMLSSORequest.URI);
	        		else
	        			d = req.getRequestDispatcher(OauthRequestAction.URI);
	        		
	        		d.forward(new SamlSsoRequestWrapper(req, u, idp), resp);
	        		return ;
    			} catch (InternalErrorException | IOException e) {
    				error = "Error guessing identity provider for "+u;
    				LogFactory.getLog(getClass()).warn("Error guessing identity provider for "+u, e);
    			}
        	} else {
	           	AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
	           	try {
		           	if (!ctx.checkUser(u)) {
		           		if (ctx.checkUser(u.toLowerCase()))
		           			u = u.toLowerCase();
		           		else if (ctx.checkUser(u.toUpperCase()))
		           			u = u.toUpperCase();
		           	}
		           	ctx.setUser(u);
	           		if (ctx.isLocked(u)) {
	           			error = "User is temporary locked";
	           		} else {
						ctx.updateAllowedAuthenticationMethods();
						ctx.onInitialStep();
	           		}
				} catch (Exception e) {
		           	error = "Cannot find suitable authentication methods";
		           	LogFactory.getLog(getClass()).warn("Cannot find suitable authentication methods", e);
				}
	           	error = null;
        	}
        }
        req.setAttribute("ERROR", error); //$NON-NLS-1$
        RequestDispatcher dispatcher = req.getRequestDispatcher(UserPasswordFormServlet.URI);
        dispatcher.forward(req, resp);
    }

    
}

class SamlSsoRequestWrapper extends HttpServletRequestWrapper {

	private String user;
	String idp;

	public SamlSsoRequestWrapper(HttpServletRequest request, String user, String idp) {
		super(request);
		this.user = user;
		this.idp = idp;
	}

	@Override
	public String getParameter(String name) {
		if ("user".equals(name))
			return user;
		if ("idp".equals(name))
			return idp;
		return super.getParameter(name);
	}

}
