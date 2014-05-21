package es.caib.seycon.idp.shibext;

import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

public class SessionPrincipal extends UsernamePrincipal {

	private String sessionString;
	
	public String getSessionString() {
		return sessionString;
	}

	public SessionPrincipal(String principalName, String sessionString) {
		super(principalName);
		this.sessionString = sessionString;
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

}
