package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.api.GroupUser;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;

public class SelectHolderGroupAction extends HttpServlet {

	public static final String URI = "/holderGroupAction"; //$NON-NLS-1$
	private static final long serialVersionUID = 1L;
	Log log = LogFactory.getLog(getClass());

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String error = null;
		try {
			log.info(">>> HOLDERGROUP - SelectHolderGroupAction.doPost");
			String hgId = req.getParameter("holderGroup"); //$NON-NLS-1$
			if (hgId!=null) {
	        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
	        	if (authCtx.isFinished()) {
	        		String un = authCtx.getCurrentUser().getUserName();
	        		Collection<GroupUser> gul = new RemoteServiceLocator().getGroupService().findUsersGroupByUserName(un);
	        		for (GroupUser gu : gul) {
	        			if (hgId.equals(gu.getGroupId().toString())) {

	        				// Context
	        				authCtx.setHolderGroupIsActive(true);
	        				authCtx.setSelectedHolderGroup(gu.getGroup());

	        				// Session
	        				HttpSession s = req.getSession();
	        				OpenIdRequest r = (OpenIdRequest) s.getAttribute(SessionConstants.OPENID_REQUEST);
	        				r.setHolderGroup(gu.getGroup());
	        		    	s.setAttribute(SessionConstants.OPENID_REQUEST, r);
	        		    	s.setAttribute(SessionConstants.OPENID_HOLDERGROUP, r.getHolderGroup());

	        		    	// Authenticator
	    	                Autenticator auth = new Autenticator();
	    	                auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, authCtx.getUsedMethod(), false, authCtx.getHostId(resp));
	    	                log.info(">>> HOLDERGROUP - authentication ok");
	    	                return;
	        			}
	        		}
            		error = "No se ha encontrado el grupo "+un; //$NON-NLS-1$
	        	} else {
	        		error = "Error genérico"; //$NON-NLS-1$
	        	}
			} else {
        		error = "No se ha seleccionado ningún elemento"; //$NON-NLS-1$
			}
		} catch (Exception e) {
			error = "An internal error has been detected: " + e.toString();
			e.printStackTrace();
		}
		if (error!=null) {
			req.setAttribute("ERROR", error); //$NON-NLS-1$
			resp.sendRedirect(SelectHolderGroupForm.URI);
		}
	}
}
