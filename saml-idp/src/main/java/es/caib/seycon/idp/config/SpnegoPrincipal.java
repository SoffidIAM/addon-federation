package es.caib.seycon.idp.config;

import java.security.Principal;

import com.soffid.iam.api.Account;

public class SpnegoPrincipal implements Principal {
	private Account account;

	public SpnegoPrincipal (Account account) {
		this.account = account;
	}

	public String getName() {
		return account.getName()+"@"+account.getSystem();
	}

}
