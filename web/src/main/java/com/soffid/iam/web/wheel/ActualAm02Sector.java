package com.soffid.iam.web.wheel;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;

import es.caib.seycon.ng.exception.InternalErrorException;

public class ActualAm02Sector {
	public boolean isDone() throws InternalErrorException, NamingException {
		boolean sp = false, idp = false;
		FederationService svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
		for (FederationMember member: svc.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "I")) {
			if (member.getClasse().equals("I") &&  member.getIdpType() == IdentityProviderType.SOFFID)
				idp = true;
		}
		sp = ! svc.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "S").isEmpty();
		return sp && idp;
	}
}
