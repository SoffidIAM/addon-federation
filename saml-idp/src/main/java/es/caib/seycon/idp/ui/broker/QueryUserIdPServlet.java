package es.caib.seycon.idp.ui.broker;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;

import es.caib.seycon.idp.ui.BaseForm;
import es.caib.seycon.ng.exception.InternalErrorException;

public class QueryUserIdPServlet extends BaseForm {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/sp-profile/user-idp"; //$NON-NLS-1$
    private ServletContext context;
    Log log = LogFactory.getLog(getClass());
    
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);

    	try {
	        String user = req.getParameter("user");
	        String idp = null;
	        if (user != null && !user.trim().isEmpty())
	        {
				idp = new RemoteServiceLocator().getFederacioService().searchIdpForUser(user);
			}
	        
	        resp.setContentType("application/json; charset=UTF-8");
	        StringBuffer sb = new StringBuffer();
	        sb.append("{");
	        if (idp != null)
	        	sb.append("\"idp\":\"")
	        	.append(idp.replaceAll("\"", "\\\\\"") )
	        	.append("\"");
	        sb.append("}");
	        ServletOutputStream out = resp.getOutputStream();
	        out.write(sb.toString().getBytes("UTF-8"));
	        out.close();
		} catch (InternalErrorException e) {
			resp.setStatus(500);
			log.warn("Error guessing user idp", e);
		}
        
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    

}
