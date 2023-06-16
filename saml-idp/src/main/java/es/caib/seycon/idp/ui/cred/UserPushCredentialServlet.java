package es.caib.seycon.idp.ui.cred;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.PushAuthenticationService;
import com.soffid.iam.addons.federation.service.UserCredentialService;
import com.soffid.iam.api.User;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.BaseForm;

public class UserPushCredentialServlet extends BaseForm {
	static Log log = LogFactory.getLog(UserPushCredentialServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/pendingPushRequest/*"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);


        String serial = req.getPathInfo().substring(1);
        try {
        	
			final UserCredentialService userCredentialService = new RemoteServiceLocator().getUserCredentialService();
        	UserCredential cred = userCredentialService.findBySerial(serial);
        	
        	JSONObject o = new JSONObject();
        	o.put("pending", false);
        	for (UserCredentialChallenge ch: new RemoteServiceLocator().getPushAuthenticationService().findPushAuthentications(serial)) {
        		if (! ch.isSolved()) {
	        		o.put("pending", true);
	        		o.put("id", ch.getId());
	        		break;
        		}        		
        	}
        	
        	byte[] b = o.toString().getBytes(StandardCharsets.UTF_8);
        	resp.setContentLength(b.length);
        	resp.setContentType("application/json");
        	resp.getOutputStream().write(b);
        } catch (Exception e) {
        	log.warn("Error validating OTP "+serial, e);
            throw new ServletException(e);
		}
    }


	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String serial = req.getPathInfo().substring(1);
		String value = req.getParameter("value");
		String id = req.getParameter("id");
		try {
	    	final PushAuthenticationService pushAuthenticationService = new RemoteServiceLocator().getPushAuthenticationService();
			for (UserCredentialChallenge ch: pushAuthenticationService.findPushAuthentications(serial)) {
	    		if (! ch.isSolved() && ch.getId().toString().equals(id)) {
	    			pushAuthenticationService.responsePushAuthentication(ch, value);
	        		break;
	    		}        		
	    	}
        	resp.setContentLength(2);
        	resp.setContentType("application/json");
        	resp.getOutputStream().write("{}".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
        	log.warn("Error registering token "+serial, e);
            throw new ServletException(e);
		}
    }
    
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		resp.addHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}

}
