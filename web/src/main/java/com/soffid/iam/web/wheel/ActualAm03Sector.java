package com.soffid.iam.web.wheel;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.zkoss.zk.ui.UiException;

import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.service.ejb.FederationService;
import com.soffid.iam.addons.federation.service.ejb.FederationServiceHome;
import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.service.ejb.OtpService;
import com.soffid.iam.addons.otp.service.ejb.OtpServiceHome;

import es.caib.seycon.ng.exception.InternalErrorException;

public class ActualAm03Sector {
	private OtpService otpService;
	private FederationService svc;
	
	public ActualAm03Sector() throws NamingException {
		otpService = (OtpService) new InitialContext().lookup(OtpServiceHome.JNDI_NAME);
		svc = (FederationService) new InitialContext().lookup(FederationServiceHome.JNDI_NAME);
	}
	
	public boolean isDone() throws InternalErrorException, NamingException {
		OtpConfig cfg = otpService.getConfiguration();
		
		
		if (cfg.isAllowEmail() || cfg.isAllowHotp() || cfg.isAllowPin() || cfg.isAllowSms() || cfg.isAllowTotp()) {
			try {
				for (FederationMember member: svc.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "I")) {
					if (member.getClasse().equals("I") &&  member.getIdpType() == IdentityProviderType.SOFFID) {
						String publicId = member.getPublicId();
						for (AuthenticationMethod am: member.getExtendedAuthenticationMethods()) {
							if (am.getDescription().equals("MFA"))
								return true;
						}
					}
				}
			} catch (Exception e) {
				throw new UiException(e);
			}

		}
		return false;
	}
}
