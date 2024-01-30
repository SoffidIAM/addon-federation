package es.caib.seycon.idp.config;

import java.security.Principal;

import org.eclipse.jetty.security.SpnegoUserPrincipal;

import com.soffid.iam.api.Account;

public class SpnegoPrincipal extends SpnegoUserPrincipal {
	private Account account;

	public SpnegoPrincipal (Account account) {
		super(account.getName(), new byte[0]);
		this.account = account;
	}

	public String getName() {
		return account.getName()+"@"+account.getSystem();
	}

}
