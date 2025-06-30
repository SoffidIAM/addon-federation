package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import com.github.scribejava.core.java8.Base64;
import com.soffid.iam.addons.federation.api.DocumentVerification;
import com.soffid.iam.addons.federation.api.FacialVerification;
import com.soffid.iam.addons.federation.api.LivenessVerification;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.IdentityVerificationService;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.MetadataScope;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.service.UserService;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.comu.TypeEnumeration;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.servei.LogonService;
import es.caib.seycon.ng.sync.servei.ServerService;

public class RegisterFacephiAction extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	Log log = LogFactory.getLog(getClass());

	public static final String URI = "/registerFacephiAction"; //$NON-NLS-1$

    private ServletContext context;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        context = config.getServletContext();
    }

    @Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		Map<String, String> params = new HashMap<String, String>();
		User u = new User();
		u.setAttributes(new HashMap<String, Object>());
		String error = null;
		JSONObject data = new JSONObject(req.getParameter("data"));
		
		boolean sendEmail = true;
		String accountName = null;
		try {
			IdpConfig config = IdpConfig.getConfig();

			HttpSession session = req.getSession();

			String relyingParty = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);

			FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

			if (!ip.isAllowRegister() && !ip.isAllowFacephiRegister()) {
				error = "Register is not allowed";
			} else {
				IdentityVerificationService svc = new RemoteServiceLocator().getIdentityVerificationService();
				
				String front = data.getString("frontDocument");
				String back = data.optString("backDocument", null);
				
				String df = svc.startDocumentVerification(ip.getPublicId(), "ES", "ID_CARD", getMime(front),
						getData(front), getData(back));
				
				DocumentVerification v;
				int attempts = 0;
				do {
					attempts ++;
					Thread.sleep(1000);
					v = svc.getDocumentVerification(ip.getPublicId(), df);
				} while (attempts < 120 && !v.isFinished() );
				
				if (!v.isSuccess()) {
					log.warn("Error validating document: "+v.getReason());
					error = "Cannot read id document. Please, try again";
				}
				else
				{
					String image = data.getString("imageFull");
					LivenessVerification pl = svc.passiveLiveness(ip.getPublicId(), getData(image));
					if (!pl.isSuccess()) {
						log.warn("Image liveness failed");
						error = "Cannot read the document data. Please, try again";
					}
					else
					{
						String tokenizedImage = data.getString("imageTokenized");
						String documentFace = data.getString("faceDocument");
						String faceImage = data.getString("image");
						String templateRaw = data.getString("templateRaw");
//						FacialVerification af = svc.authenticateFacial(ip.getPublicId(), getData(tokenizedImage), getData(documentFace));
						FacialVerification af = svc.authenticateFacial(ip.getPublicId(), 
								getData(faceImage), getData(templateRaw));
						if (af.isSuccess()) {
							String userType = ip.getUserTypeToRegister();
				            HtmlGenerator g = new HtmlGenerator(context, req);
				            g.addArgument("ERROR", (String) req.getAttribute("ERROR")); //$NON-NLS-1$ //$NON-NLS-2$
				            
				            g.addArgument("previous_firstName", v.getFirstName());
				            g.addArgument("previous_lastName", v.getLastName());
				            g.addArgument("previous_userName", v.getIdNumber());
					        g.addArgument("refreshUrl", URI); //$NON-NLS-1$
				            g.addArgument("registerUrl", RegisterAction.URI);
				            g.addArgument("loginPage", UserPasswordFormServlet.URI);
				            
				        	g.addArgument("policy", 
				        			config.getFederationService().getPolicyDescriptionForUserType(userType, IdpConfig.getConfig().getSystem().getName()));
				
				            g.generate(resp, "registerFacephi.html"); //$NON-NLS-1$
							
						} else {
							log.warn("Face does not match document face");
							error = "Cannot read the document data. Please, try again";
						}
					}
				}

			}
		} catch (InternalErrorException e) {
			final String uwm = "es.caib.bpm.toolkit.exception.UserWorkflowException: ";
			int i = e.getMessage().indexOf(uwm);
			if (i >= 0)
				error = e.getMessage().substring(i + uwm.length());
			else
				error = "An internal error has been detected: " + e.getMessage();
			e.printStackTrace();
		} catch (Exception e) {
			error = "An internal error has been detected: " + e.toString();
			e.printStackTrace();
		}

		if (error != null) {
			req.setAttribute("ERROR", error); //$NON-NLS-1$
			req.setAttribute("register", params); //$NON-NLS-1$

			RequestDispatcher dispatcher = req.getRequestDispatcher(RegisterFormServlet.URI);
			dispatcher.forward(req, resp);
		}
	}

	private String getMime(String front) {
		if (front == null)
			return null;
		int i = front.indexOf(":");
		int j = front.indexOf(";");
		return front.substring(i+1, j);
	}

	private byte[] getData(String front) {
		if (front == null)
			return null;
		int i = front.indexOf(",");
		if (i > 0)
			return Base64.getDecoder().decode(front.substring(i+1));
		else
			return Base64.getDecoder().decode(front);
	}
}
