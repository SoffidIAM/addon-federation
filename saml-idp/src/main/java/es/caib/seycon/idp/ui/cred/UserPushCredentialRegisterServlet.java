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
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.UserCredentialService;
import com.soffid.iam.api.User;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.BaseForm;

public class UserPushCredentialRegisterServlet extends BaseForm {
	static Log log = LogFactory.getLog(UserPushCredentialRegisterServlet.class);
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/rpc/*"; //$NON-NLS-1$
    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.doGet(req, resp);


        String hash = req.getPathInfo().substring(1);
        try {
        	
			final UserCredentialService userCredentialService = new RemoteServiceLocator().getUserCredentialService();
        	User user = userCredentialService.findUserForNewCredentialURI(hash);
        	
        	JSONObject o = new JSONObject();
        	if (user == null) {
        		o.put("success", false);
        		o.put("cause", "Wrong URL");
        	} else {
				UserCredential credential = new UserCredential();
				credential.setCreated(new Date());
				credential.setSerialNumber( userCredentialService.generateNextSerial() );
				credential.setDescription ( "Push token "+credential.getSerialNumber() );
				credential.setType(UserCredentialType.PUSH);
				
				SecureRandom sr = new SecureRandom();
				byte b[] = new byte[10];
				sr.nextBytes(b);
				String s = new Base32().encodeAsString(b);
				credential.setKey(s);
				credential.setUserId(user.getId());
				userCredentialService.create(credential);
				userCredentialService.cancelNewCredentialURI(hash);
        		o.put("success", true);
        		while (s.endsWith("=")) s = s.substring(0, s.length()-1);
        		o.put("key", s);
        		o.put("company", IdpConfig.getConfig().getFederationMember().getOrganization());
        		o.put("id", credential.getSerialNumber());
        	}
        	byte[] b = o.toString().getBytes(StandardCharsets.UTF_8);
        	resp.setContentLength(b.length);
        	resp.setContentType("application/json");
        	resp.getOutputStream().write(b);
        } catch (Exception e) {
        	log.warn("Error registering token "+hash, e);
            throw new ServletException(e);
		}
    }


	@Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet (req, resp);
    }
    
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
		resp.addHeader("Access-Control-Allow-Headers", "Authorization");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}

}
