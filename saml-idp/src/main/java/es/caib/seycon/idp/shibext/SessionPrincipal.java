package es.caib.seycon.idp.shibext;

import com.soffid.iam.addons.federation.api.LevelOfAssuranceEnum;

import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;

public class SessionPrincipal extends UsernamePrincipal {

	private String sessionString;
	private String holderGroup;
	private LevelOfAssuranceEnum loa;
	
	public String getSessionString() {
		return sessionString;
	}

	public SessionPrincipal(String principalName, String sessionString, String holderGroup,
			LevelOfAssuranceEnum loa) {
		super(principalName);
		this.sessionString = sessionString;
		this.holderGroup = holderGroup;
		this.loa = loa;
	}

	public LevelOfAssuranceEnum getLoa() {
		return loa;
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public String getHolderGroup() {
		return holderGroup;
	}

}
