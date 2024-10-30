package es.caib.seycon.idp.shibext;

import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

public class SessionPrincipal extends UsernamePrincipal {

	private String sessionString;
	private String holderGroup;
	
	public String getSessionString() {
		return sessionString;
	}

	public SessionPrincipal(String principalName, String sessionString, String holderGroup) {
		super(principalName);
		this.sessionString = sessionString;
		this.holderGroup = holderGroup;
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public String getHolderGroup() {
		return holderGroup;
	}

}
