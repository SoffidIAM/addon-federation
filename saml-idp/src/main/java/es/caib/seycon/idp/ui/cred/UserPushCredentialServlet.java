package es.caib.seycon.idp.ui.cred;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.PushAuthenticationService;
import com.soffid.iam.addons.federation.service.UserCredentialService;

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
	        		if (ch.getImages() != null) {
	        			JSONArray images = new JSONArray();
	        			o.put("images", images);
	        			JSONArray imageUrls = new JSONArray();
	        			o.put("imageUrls", imageUrls);
	        			for (int i = 0 ; i < ch.getIdentifiers().length; i++) {
	        				images.put(ch.getIdentifiers()[i]);
	        				imageUrls.put(ch.getImages()[i]);
	        			}
	        		}
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
        String action = req.getParameter("action");
        try {
        	final PushAuthenticationService pushAuthenticationService = new RemoteServiceLocator().getPushAuthenticationService();
	        if ("register".equals(action)) {
	        	String os = req.getParameter("os");
	        	String model = req.getParameter("model");
	        	String version = req.getParameter("version");
	        	String channel = req.getParameter("channel");
	        	pushAuthenticationService.updatePushAuthenticationToken(serial, channel, os, model, version);
	        	resp.setContentLength(2);
	        	resp.setContentType("application/json");
	        	resp.getOutputStream().write("{}".getBytes(StandardCharsets.UTF_8));
	        } else {
	        	String value = req.getParameter("value");
	        	String id = req.getParameter("id");
	        	for (UserCredentialChallenge ch: pushAuthenticationService.findPushAuthentications(serial)) {
	        		if (! ch.isSolved() && ch.getId().toString().equals(id)) {
	        			pushAuthenticationService.responsePushAuthentication(ch, value);
	        			break;
	        		}        		
	        	}
	        	resp.setContentLength(2);
	        	resp.setContentType("application/json");
	        	resp.getOutputStream().write("{}".getBytes(StandardCharsets.UTF_8));
	        }
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
