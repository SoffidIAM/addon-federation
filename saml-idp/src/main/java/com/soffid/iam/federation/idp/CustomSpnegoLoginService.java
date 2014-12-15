package com.soffid.iam.federation.idp;

import java.security.PrivilegedAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.SpnegoLoginService;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.component.AbstractLifeCycle;

import es.caib.seycon.idp.config.PasswordCallbackHandler;
import es.caib.seycon.ng.comu.Password;

public class CustomSpnegoLoginService extends AbstractLifeCycle implements LoginService {
	SpnegoLoginService parentService;
	String name;
	
	public CustomSpnegoLoginService(SpnegoLoginService parentService,
			String name) {
		super();
		this.parentService = parentService;
		this.name = name;
	}

	public UserIdentity login(final String username, final Object credentials) {
        try {
			LoginContext lc = new LoginContext("com.sun.security.jgss.accept");
			lc.login ();
			Subject subject = lc.getSubject();
			System.out.println ("Subject = "+subject.toString());
			new LoginContext("com.sun.security.jgss.initiate").login();
			return parentService.login(username, credentials);
		} catch (LoginException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	protected void doStart() throws Exception {
		parentService.start();
	}

	public String getName() {
		return name;
	}

	public boolean validate(UserIdentity user) {
		return parentService.validate(user);
	}

	public IdentityService getIdentityService() {
		return parentService.getIdentityService();
	}

	public void setIdentityService(IdentityService service) {
		parentService.setIdentityService(service);
	}

	public void logout(UserIdentity user) {
		parentService.logout(user);
	}
	
}
