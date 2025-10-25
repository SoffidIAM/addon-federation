package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.common.ProgressiveProfile;
import com.soffid.iam.api.Group;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.server.RoleRestrictionException;

public class ProgressiveProfileAction extends HttpServlet {
	public static final String URI = "/progressiveProfileAction"; //$NON-NLS-1$
	private static final long serialVersionUID = 1L;
	Log log = LogFactory.getLog(getClass());

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String error = null;
		try {
        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
        	ProgressiveProfile pp = authCtx.getProgressiveProfile();
        	if (authCtx.isFinished() && pp != null) {
        		HashMap<String,String> vars = new HashMap<>();
        		for (String field: pp.getFields()) {
        			vars.put(field, req.getParameter(field));
        		}
        		new RemoteServiceLocator().getFederacioService()
        			.completeUserProfile(authCtx.getUser(),
        					vars,
        					pp);
        		authCtx.completeProgressiveProfile();

			}
        	// Authenticator
        	Autenticator auth = new Autenticator();
        	auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, 
        			authCtx.getUsedMethod(), 
        			authCtx.getLevelOfAssurance(),
        			false, authCtx.getHostId(resp));
        	return;
        } catch (RoleRestrictionException e) {
            error = Messages.getString("SystemAccessRestricted"); //$NON-NLS-1$
		} catch (Exception e) {
			error = "An internal error has been detected: " + e.toString();
			e.printStackTrace();
		}
		if (error!=null) {
			req.setAttribute("ERROR", error); //$NON-NLS-1$
			req.getRequestDispatcher(CompleteProfileForm.URI)
				.forward(req, resp);
		}
	}
}
