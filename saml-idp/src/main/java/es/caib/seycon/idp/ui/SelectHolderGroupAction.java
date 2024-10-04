package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.GroupUser;

import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;

public class SelectHolderGroupAction extends HttpServlet {

	public static final String URI = "/holderGroupAction"; //$NON-NLS-1$
	private static final long serialVersionUID = 1L;
	private LogRecorder logRecorder = LogRecorder.getInstance();

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String error = null;
		try {
			String hgId = req.getParameter("holderGroup"); //$NON-NLS-1$
			if (hgId!=null) {
	        	AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
	        	if (authCtx.isFinished()) {
	        		String un = authCtx.getCurrentUser().getUserName();
	        		Collection<GroupUser> gul = ServiceLocator.instance().getGroupService().findUsersGroupByUserName(un);
	        		for (GroupUser gu : gul) {
	        			if (hgId.equals(gu.getGroupId().toString())) {
	        				authCtx.setHolderGroupIsActive(true);
	        				authCtx.setHolderGroupSelected(hgId);
	    	                Autenticator auth = new Autenticator();
	    	                auth.autenticate2(authCtx.getUser(), getServletContext(), req, resp, authCtx.getUsedMethod(), false, authCtx.getHostId(resp));
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
		req.setAttribute("ERROR", error); //$NON-NLS-1$
		resp.sendRedirect(SelectHolderGroupForm.URI);

//		if (error != null) {
//	        req.setAttribute("ERROR", error); //$NON-NLS-1$
//	        RequestDispatcher dispatcher = req.getRequestDispatcher(ErrorServlet.URI);
//	        dispatcher.forward(req, resp);
//		}
	}
}
