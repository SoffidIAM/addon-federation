package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.service.UserService;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class RegisterAction extends HttpServlet {
	public static final String REGISTER_SERVICE_PROVIDER = "RegisterServiceProvider";

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	LogRecorder logRecorder = LogRecorder.getInstance();

	public static final String URI = "/registerAction"; //$NON-NLS-1$

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		AuthenticationMethodFilter amf = new AuthenticationMethodFilter(req);
		if (!amf.allowUserPassword())
			throw new ServletException("Authentication method not allowed"); //$NON-NLS-1$

		String error = null;
		String un = req.getParameter("userName"); //$NON-NLS-1$
		String gn = req.getParameter("givenName"); //$NON-NLS-1$
		String sn = req.getParameter("surName");
		String email = req.getParameter("email");
		String p1 = req.getParameter("j_password1");
		String p2 = req.getParameter("j_password2");

		boolean sendEmail = true;
		String accountName = null;
		try {
			if (!amf.getIdentityProvider().isAllowRegister()) {
				throw new ServletException("Not authorized to self register");
			}

			IdpConfig config = IdpConfig.getConfig();

			HttpSession session = req.getSession();

			String relyingParty = (String) session.getAttribute(ExternalAuthnSystemLoginHandler.RELYING_PARTY_PARAM);

			FederationMember ip = config.findIdentityProviderForRelyingParty(relyingParty);

			sendEmail = ip.getMailHost() != null && !ip.getMailHost().trim().isEmpty();
			String userType = ip.getUserTypeToRegister();

			if (un == null || un.isEmpty()) {
				error = "User name is required";
			} else if (un.length() > 10) {
				error = "User name cannot have more than ten characters";
			} else if (gn == null || gn.isEmpty()) {
				error = "Given name is required";
			} else if (sn == null || sn.isEmpty()) {
				error = "Surname is required";
			} else if (email == null || email.isEmpty()) {
				error = "Email address is required";
			} else if (!email.contains("@")) {
				error = "Email address is not valid";
			} else if (p1 == null || p1.length() == 0) {
				error = Messages.getString("PasswordChangeRequiredAction.missing.pasword"); //$NON-NLS-1$
			} else if (p2 == null || p2.length() == 0) {
				error = Messages.getString("PasswordChangeRequiredAction.missing.second.password"); //$NON-NLS-1$
			} else if (!p1.equals(p2)) {
				error = Messages.getString("PasswordChangeRequiredAction.password.mismatch"); //$NON-NLS-1$
			} else if (!ip.isAllowRegister()) {
				error = "Register is not allowed";
			} else {

				PasswordManager pm = new PasswordManager();
				com.soffid.iam.api.PolicyCheckResult result = pm.checkPolicy(userType, new Password(p1));
				if (result.isValid()) {
					UserService usuariService = new RemoteServiceLocator().getUserService();
					AdditionalDataService dadesService = new RemoteServiceLocator().getAdditionalDataService();
					User usuari = usuariService.findUserByUserName(un);
					if (usuari != null)
						error = String.format("The user name %s is in use. Please, selecte another one", un);
					else {
						usuari = new User();
						usuari.setUserName(un);
						usuari.setFirstName(gn);
						usuari.setLastName(sn);
						usuari.setActive(Boolean.valueOf(!sendEmail));
						usuari.setPrimaryGroup(ip.getGroupToRegister());
						usuari.setCreatedDate(Calendar.getInstance());
						usuari.setMultiSession(Boolean.FALSE);
						usuari.setMailServer("null");
						usuari.setHomeServer("null");
						usuari.setProfileServer("null");
						usuari.setUserType(ip.getUserTypeToRegister());
						usuari.setComments(String.format("Self registered from IP %s", req.getRemoteAddr()));
						Map<String, String> dades = new HashMap<String, String>();
						dades.put("EMAIL", email);
						dades.put(REGISTER_SERVICE_PROVIDER, relyingParty);

						config.getFederationService().registerUser(config.getSystem().getName(), usuari, dades,
								new Password(p1));

						if (sendEmail) {
							String url = "https://" + config.getHostName() + ":" + config.getStandardPort()
									+ ActivateUserAction.URI + "?rp=" + relyingParty;
							config.getFederationService().sendActivationEmail(un, ip.getMailHost(),
									ip.getMailSenderAddress(), url, ip.getOrganization());

						} else {
							accountName = un;
						}
					}
				} else
					error = result.getReason();
			}
		} catch (InternalErrorException e) {
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
								ctx.getUsedMethod(), false);
						return;
					}
				} catch (Exception e) {
					error = "An internal error has been detected: " + e.toString();
					e.printStackTrace();
					req.setAttribute("ERROR", error); //$NON-NLS-1$
					req.setAttribute("previousUserName", un); //$NON-NLS-1$
					req.setAttribute("previousSurName", sn); //$NON-NLS-1$
					req.setAttribute("previousGivenName", gn); //$NON-NLS-1$
					req.setAttribute("previousEmail", email);//$NON-NLS-1$

					RequestDispatcher dispatcher = req.getRequestDispatcher(RegisterFormServlet.URI);
					dispatcher.forward(req, resp);
				}
			}
		} else {
			req.setAttribute("ERROR", error); //$NON-NLS-1$
			req.setAttribute("previousUserName", un); //$NON-NLS-1$
			req.setAttribute("previousSurName", sn); //$NON-NLS-1$
			req.setAttribute("previousGivenName", gn); //$NON-NLS-1$
			req.setAttribute("previousEmail", email);//$NON-NLS-1$

			RequestDispatcher dispatcher = req.getRequestDispatcher(RegisterFormServlet.URI);
			dispatcher.forward(req, resp);
		}
	}

}
