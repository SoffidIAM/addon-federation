package com.soffid.iam.web.addons.federation.web.wheel;

import java.lang.reflect.InvocationTargetException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.xml.utils.URI;
import org.apache.xml.utils.URI.MalformedURIException;
import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Radiogroup;
import org.zkoss.zul.Timer;
import org.zkoss.zul.Window;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.RootCertificate;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.addons.federation.service.SelfCertificateService;
import com.soffid.iam.addons.federation.service.UserCredentialService;
import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.service.OtpService;
import com.soffid.iam.api.AuthorizationRole;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.User;
import com.soffid.iam.common.security.SoffidPrincipal;
import com.soffid.iam.service.ApplicationService;
import com.soffid.iam.service.AuthorizationService;
import com.soffid.iam.sync.service.CertificateEnrollService;
import com.soffid.iam.utils.Security;
import com.soffid.iam.web.component.CustomField3;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.Wizard;
import es.caib.zkib.zkiblaf.Missatgebox;

public class Am03Handler extends Window implements AfterCompose {
	private Wizard wizard;
	private Radiogroup radiogroup;
	private Radiogroup radiogroup2;
	private CustomField3 message;
	private CustomField3 users;
	private CustomField3 date;
	private Radiogroup radiogroup3;
	private Timer timer;
	private Exception lastException;
	private boolean finished = false;
	private String publicId;

	@Override
	public void afterCompose() {
		wizard = (Wizard) getFellow("wizard");
		radiogroup = (Radiogroup) getFellow("radiogroup");
		radiogroup2 = (Radiogroup) getFellow("radiogroup2");
		radiogroup3 = (Radiogroup) getFellow("radiogroup3");
		message = (CustomField3) getFellow("message");
		users = (CustomField3) getFellow("users");
		date = (CustomField3) getFellow("date");
		timer = (Timer) getFellow("timer");
	}
	
	public void back(Event ev) {
		if (wizard.getSelected() <= 0)
			detach();
		else {
			wizard.previous();
		}
	}
	
	public void next(Event ev) throws Exception {
		switch (wizard.getSelected()) {
		case 0: 
			if (radiogroup.getSelectedItem() == null)
			{
				Missatgebox.avis(Labels.getLabel("selfcertificate.selectType"));
				break;
			}
			generateMessage();
			wizard.next();
			break;
		case 1:
			if (radiogroup2.getSelectedItem() == null)
			{
				Missatgebox.avis(Labels.getLabel("selfcertificate.selectType"));
				break;
			}
			if ("some".equals(radiogroup2.getSelectedItem().getValue()))
			{
				if (! users.attributeValidateAll())
					break;
			}
			wizard.next();
			Calendar c = Calendar.getInstance();
			c.add(Calendar.DAY_OF_MONTH, 14);
			date.setValue(c.getTime());
			radiogroup3.setSelectedItem(null);
			date.setVisible(false);
			break;
		case 2:
			if (radiogroup3.getSelectedItem() == null)
			{
				Missatgebox.avis(Labels.getLabel("selfcertificate.selectType"));
				break;
			}
			if (date.isVisible() && ! date.attributeValidateAll())
				break;
			wizard.next();
			applyChanges();
			break;
		case 3:
			if (publicId != null)
				Executions.getCurrent().sendRedirect("/addon/federation/providers.zul?filter="+publicId, "_blank");
			detach();
		default:
			wizard.next();
			break;
		}
	}

	private void applyChanges() {
		timer.start();
		final SoffidPrincipal principal = Security.getSoffidPrincipal();
		new Thread(() -> {
			Security.nestedLogin(principal);
			try {
				OtpService otpSvc = (OtpService) ServiceLocator.instance().getService(OtpService.SERVICE_NAME);
				FederationService federationService = (FederationService) ServiceLocator.instance().getService(FederationService.SERVICE_NAME);
				Role role = createSoffidUserRole();
				grantPermission (role);
				configureOtp(otpSvc);
				configureCert();
				
				notifyUsers();
				
				enableRule(federationService);
			} catch (Exception e) {
				lastException = e;
			} finally {
				finished  = true;
				Security.nestedLogoff();
			}
		}).start();
	}

	private void enableRule(FederationService federationService) throws InternalErrorException {
		for (FederationMember member: federationService.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "I")) {
			if (member.getClasse().equals("I") &&  member.getIdpType() == IdentityProviderType.SOFFID) {
				publicId = member.getPublicId();
				boolean found = false;
				for (AuthenticationMethod am: member.getExtendedAuthenticationMethods()) {
					if (am.getDescription().equals("MFA")) {
						configure(am);
						found = true;
					}
				}
				if (!found) {
					AuthenticationMethod am = new AuthenticationMethod();
					configure(am);
					am.setDescription("MFA");
					am.setAlwaysAskForCredentials(false);
					member.getExtendedAuthenticationMethods().add(am);
				}
				federationService.update(member);
			}
		}
		
	}

	private void configure(AuthenticationMethod am) {
		if ("none".equals(radiogroup3.getSelectedItem().getValue()))
			am.setExpression("false");
		else {
			Date d = (Date) date.getValue();
			String dateLimit = "start = new java.text.SimpleDateFormat(\"yyyy-MM-dd HH:mm\")\n  .parse(\""+
					new SimpleDateFormat("yyyy-MM-dd HH:mm").format(d)
					+"\");\n"
					+"return start.before(new java.util.Date())";
			if ("all".equals(radiogroup3.getSelectedItem().getValue())) {
				am.setExpression(dateLimit+";");
			}
			else if ("sms".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasSms;");				
			}
			else if ("email".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasMail;");				
			}
			else if ("totp".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasTotp;");				
			}
			else if ("hotp".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasHotp;");				
			}
			else if ("pin".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasPin;");				
			}
			else if ("fido".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasFidoToken;");				
			}
			else if ("cert".equals(radiogroup.getSelectedItem().getValue()))
			{
				am.setExpression(dateLimit+" && hasCertificate;");				
			}
		}
		if ("sms".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PS");				
		}
		else if ("email".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PM");
		}
		else if ("totp".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PO");
		}
		else if ("hotp".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PO");
		}
		else if ("pin".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PI");
		}
		else if ("fido".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PF");
		}
		else if ("cert".equals(radiogroup.getSelectedItem().getValue()))
		{
			am.setAuthenticationMethods("PC");
		}
	}

	private void notifyUsers() throws Exception {
		if ("all".equals(radiogroup2.getSelectedItem().getValue())) {
			int start = 0;
			do {
				PagedResult<User> list = ServiceLocator.instance().getUserService().findUserByTextAndFilter(null, null, start, 500);
				if (list.getResources().isEmpty())
					break;
				for (User user: list.getResources()) {
					if (user.getActive().booleanValue()) {
						notifyUser(user);
					}
					start ++;
				}
			} while (true);
		}
		if ("some".equals(radiogroup2.getSelectedItem().getValue())) {
			for (Object user: users.getValueObjects()) {
				notifyUser((User) user);
			}
		}
	}

	private void notifyUser(User user) throws Exception {
		ServiceLocator.instance().getMailService().sendHtmlMailToActors(
				new String[] {user.getUserName()}, 
				Labels.getLabel("federation.mfa.mailSubject"),
				translate(message.getValue().toString(), user));
	}

	protected String translate(String string, User user) throws Exception {
		int pos = 0;
		StringBuffer sb = new StringBuffer();
		while (true) {
			int next = string.indexOf("${", pos);
			if (next < 0) break;
			
			int end = string.indexOf("}", next);
			if (end < 0) break;
			
			sb.append(string.substring(pos, next));
			
			String tag = string.substring(next + 2, end);
			final Object v = PropertyUtils.getProperty(user, tag);
			sb.append(v == null ? "":  v.toString());
			
			pos = end + 1;
		}
		sb.append(string.substring(pos));
		return sb.toString();
	}

	private void configureCert() throws InternalErrorException {
		if ("cert".equals(radiogroup.getSelectedItem().getValue())) {
			SelfCertificateService svc = (SelfCertificateService) ServiceLocator.instance().getService(SelfCertificateService.SERVICE_NAME);
			for (RootCertificate cert: svc.getRootCertificates()) {
				if (! cert.isExternal() && !cert.isObsolete())
					return;
			}
			RootCertificate rc = new RootCertificate();
			Calendar c = Calendar.getInstance();
			rc.setCreationDate(c);
			c = Calendar.getInstance();
			c.add(Calendar.YEAR, 10*3650);
			rc.setExpirationDate(c);
			rc.setExternal(false);
			rc.setObsolete(false);
			rc.setOrganizationName("Soffid");
			rc.setUserCertificateMonths( 24 );
			svc.createRootCertificate(rc);
		}
	}

	private void configureOtp(OtpService otpSvc) throws InternalErrorException {
		OtpConfig cfg = otpSvc.getConfiguration();
		String type = radiogroup.getSelectedItem().getValue();
		if ("email".equals(type)) {
			cfg.setAllowEmail(true);
			otpSvc.update(cfg);
		}
		if ("sms".equals(type)) {
			cfg.setAllowSms(true);
			otpSvc.update(cfg);
		}
		if ("totp".equals(type)) {
			cfg.setAllowTotp(true);
			otpSvc.update(cfg);			
		}
		if ("hotp".equals(type)) {
			cfg.setAllowHotp(true);
			otpSvc.update(cfg);			
		}
		if ("pin".equals(type)) {
			cfg.setAllowPin(true);
			otpSvc.update(cfg);			
		}
	}

	private void grantPermission(Role role) throws InternalErrorException {
		if ("fido".equals(radiogroup.getSelectedItem().getValue())) {
			grant("federation:token:user", role);
			grant("selfservice:federation-credentials:show", role);
		}
		else if ("cert".equals(radiogroup.getSelectedItem().getValue())) {
			grant("federation:certificate:user", role);
			grant("selfservice:federation-credentials:show", role);
		}
		else {
			grant("otp:user", role);
		}
	}

	private void grant(String authName, Role role) throws InternalErrorException {
		AuthorizationService autService = ServiceLocator.instance().getAuthorizationService();
		for (AuthorizationRole auth0: autService.getAuthorizationRoles(authName)) {
			if (auth0.getRole().getId().equals(role.getId()))
				return; // Already granted
		}
		AuthorizationRole auth = new AuthorizationRole();
		auth.setAuthorization(authName);
		auth.setRole(role);
		autService.create(auth );
	}

	private Role createSoffidUserRole() throws InternalErrorException {
		final ApplicationService applicationService = ServiceLocator.instance().getApplicationService();
		Role role = applicationService.findRoleByNameAndSystem("SOFFID_USER", "soffid");
		if (role == null) {
			role = new Role();
			role.setName("SOFFID_USER");
			role.setSystem("soffid");
			role.setInformationSystemName("SOFFID");
			role.setDescription("Soffid user");
			role = applicationService.create(role);
			RoleGrant rg = new RoleGrant();
			rg.setOwnerGroup("world");
			rg.setRoleId(role.getId());
			role.getGranteeGroups().add(rg);
			applicationService.update(role);
		}
		return role;
	}

	private void generateMessage() throws MalformedURIException {
		HttpServletRequest req = (HttpServletRequest) Executions.getCurrent().getNativeRequest();
		String referer = req.getHeader("referer");
		URI uri = new URI(referer);
		String type = radiogroup.getSelectedItem().getValue();
		String t = "";
		if ("email".equals(type)) {
			uri.setPath("/soffid/addon/otp/otp.zul?wizard=email");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to register your authentication email address.<br>"
					+ "It will be used by Soffid to verify your identity.";
			
		}
		if ("sms".equals(type)) {
			uri.setPath("/soffid/addon/otp/otp.zul?wizard=sms");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to register your authentication phone number.<br>"
					+ "It will be used by Soffid to verify your identity.";
			
		}
		if ("totp".equals(type)) {
			uri.setPath("/soffid/addon/otp/otp.zul?wizard=totp");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to configure your OTP application.<br>"
					+ "It will be used by Soffid to verify your identity.";
			
		}
		if ("hotp".equals(type)) {
			uri.setPath("/soffid/addon/otp/otp.zul?wizard=hotp");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to configure your OTP application.<br>"
					+ "It will be used by Soffid to verify your identity.";
			
		}
		if ("pin".equals(type)) {
			uri.setPath("/soffid/addon/otp/otp.zul?wizard=pin");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to register your authentication PIN.<br>"
					+ "It will be asked by Soffid to verify your identity.";
			
		}
		if ("cert".equals(type)) {
			uri.setPath("/soffid/addon/federation/tokens.zul?wizard=cert");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to generate your personal digital certificate.<br>"
					+ "It will be asked by Soffid to verify your identity.";
			
		}
		if ("fido".equals(type)) {
			uri.setPath("/soffid/addon/federation/tokens.zul?wizard=fido");
			t = "Please, follow this <a href='"+uri.toString()+"'>link</a>"
					+ " to register your FIDO token.<br>"
					+ "It will be asked by Soffid to verify your identity.";
			
		}
		message.setValue("Dear ${fullName},<br><br>"+t+"<br><br>Sincerely yours, "+
				Security.getSoffidPrincipal().getFullName());
		radiogroup2.setSelectedItem(null);
		users.setVisible(false);
	}
	
	public void changeMethod(Event e) {
		users.setVisible(false);
		if (radiogroup2 != null) {
			if ("some".equals(radiogroup2.getSelectedItem().getValue()))
				users.setVisible(true);
		}
	}
	
	public void changeActivation(Event e) {
		date.setVisible(! "none".equals(radiogroup3.getSelectedItem().getValue()));
	}
	
	public void onTimer(Event ev) throws Exception {
		if (finished) {
			timer.stop();
			getFellow("step3Wait").setVisible(false);
			getFellow("finish").setVisible(true);
			if (lastException != null) {
				detach();
				throw lastException;
			}
		}
	}
}
