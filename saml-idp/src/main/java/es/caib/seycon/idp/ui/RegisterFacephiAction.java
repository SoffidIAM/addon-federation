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
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.FederationMember;
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

public class RegisterFacephiAction extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

	public static final String URI = "/registerFacephiAction"; //$NON-NLS-1$

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
			for ( Enumeration<String> e = req.getParameterNames(); e.hasMoreElements(); ) {
				String pn = e.nextElement();
				Object value = req.getParameter(pn);
				if (pn.startsWith("reg_") && value != null) {
					String attName = pn.substring(4);
					params.put(attName, (String) value);
					for (DataType dt: new com.soffid.iam.remote.RemoteServiceLocator()
								.getAdditionalDataService()
								.findDataTypesByObjectTypeAndName2(User.class.getName(), attName)) {
						if (dt.getType() == TypeEnumeration.DATE_TIME_TYPE)
							value = new SimpleDateFormat("yyyy-MM-dd HH:mm").parse((String) value);
						if (dt.getType() == TypeEnumeration.DATE_TYPE)
							value = new SimpleDateFormat("yyyy-MM-dd").parse((String) value);
						if (dt.getType() == TypeEnumeration.BOOLEAN_TYPE)
							value = "true".equals(value);
						if (Boolean.TRUE.equals(dt.getBuiltin()))
							PropertyUtils.setProperty(u, attName, value);
						else {
							u.getAttributes().put(attName, value);						
						}
					}
				}
			}
			
			AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
			if (!amf.getIdentityProvider().isAllowRegister()) {
				throw new ServletException("Not authorized to self register");
			}

			IdpConfig config = IdpConfig.getConfig();

			HttpSession session = req.getSession();

			String relyingParty = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);

			FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

			String userType = ip.getUserTypeToRegister();

			if (!ip.isAllowRegister()) {
				error = "Register is not allowed";
			} else {
				UserService usuariService = new RemoteServiceLocator().getUserService();
				AdditionalDataService dadesService = new RemoteServiceLocator().getAdditionalDataService();
				if (u.getUserName() != null && 
						usuariService.findUserByUserName(u.getUserName()) != null) {
					error = String.format("The user name %s is in use. Please, selecte another one", u.getUserName());
				}
				else {
					u.setId(null);
					u.setActive(true);
					u.setMultiSession(Boolean.FALSE);
					u.setPrimaryGroup(ip.getGroupToRegister());
					u.setUserType(ip.getUserTypeToRegister());
					u.setComments(String.format("Self registered from IP %s", req.getRemoteAddr()));
					Map<String, Object> dades = u.getAttributes();

					String url = "https://" + config.getHostName() + ":" + config.getStandardPort()
								+ ActivateUserAction.URI + "?rp=" + relyingParty;

					u = config.getFederationService().registerUser(
							config.getFederationMember().getPublicId(),
							url,
							config.getSystem().getName(), u, dades,
							new Password(null));
					sendEmail = ! u.getActive();
					accountName = u.getUserName();
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

		if (error == null) {
			if (sendEmail) {
				RequestDispatcher dispatcher = req.getRequestDispatcher(RegisteredFormServlet.URI);
				dispatcher.forward(req, resp);
			} else {
				try {
					AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
					ctx.authenticated(accountName, "P", resp);
					ctx.store(req);
					if (ctx.isFinished()) {
						new Autenticator().autenticate2(accountName, getServletContext(), req, resp,
								ctx.getUsedMethod(), false, ctx.getHostId(resp));
						return;
					}
				} catch (Exception e) {
					error = Messages.getString("UserPasswordAction.internal.error");
		            LogFactory.getLog(getClass()).info("Error registering user ", e);
					req.setAttribute("ERROR", error); //$NON-NLS-1$
					req.setAttribute("register", params); //$NON-NLS-1$

					RequestDispatcher dispatcher = req.getRequestDispatcher(RegisterFormServlet.URI);
					dispatcher.forward(req, resp);
				}
			}
		} else {
			req.setAttribute("ERROR", error); //$NON-NLS-1$
			req.setAttribute("register", params); //$NON-NLS-1$

			RequestDispatcher dispatcher = req.getRequestDispatcher(RegisterFormServlet.URI);
			dispatcher.forward(req, resp);
		}
	}

}
