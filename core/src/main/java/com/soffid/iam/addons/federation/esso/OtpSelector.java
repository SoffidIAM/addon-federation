package com.soffid.iam.addons.federation.esso;

import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.FederationServiceLocator;
import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.api.adaptive.ActualAdaptiveEnvironment;
import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.addons.federation.service.GeoInformationService;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.utils.ConfigurationCache;

import es.caib.seycon.ng.exception.InternalErrorException;

public class OtpSelector {
	FederationService fs = FederationServiceLocator.instance().getFederationService();
	UserBehaviorService ubs = FederationServiceLocator.instance().getUserBehaviorService();
	
	public boolean requestChallenge(Challenge challenge) throws InternalErrorException, IOException {
 		String idpName = ConfigurationCache.getProperty("addon.federation.essoidp");
 		if (idpName == null)
 			return true;
 		else
 			return updateChallenge(challenge, idpName, false);
	}
	
 	public boolean updateChallenge(Challenge challenge, String idpName, boolean text) throws InternalErrorException, IOException {
 		if (idpName == null && challenge.getIdentityProvider() != null)
 			idpName = challenge.getIdentityProvider();
		FederationMember idp = null;
		if (idpName != null)
			idp = fs.findFederationMemberByPublicId(idpName);
		if ( idp != null ) {
			ActualAdaptiveEnvironment env = new ActualAdaptiveEnvironment(challenge.getUser(), challenge.getHost().getName(), challenge.getHost().getIp(), false, true);
			env.setService((UserBehaviorService)
					ServiceLocator.instance()
					.getService(UserBehaviorService.SERVICE_NAME));
			env.setGeoInformationService((GeoInformationService) 
					ServiceLocator.instance()
					.getService(GeoInformationService.SERVICE_NAME));
			AuthenticationMethod m = ubs.getAuthenticationMethod(idp, env );
			boolean accepted = false;
			StringBuffer otpType = new StringBuffer();
			for ( String s: m.getAuthenticationMethods().split(" "))
			{
				if (challenge.getType() == Challenge.TYPE_KERBEROS && s.startsWith("K") ||
						challenge.getType() == Challenge.TYPE_PASSWORD && s.startsWith("P")) {
					accepted = true;
					if (s.length() > 1) {
						char next = s.charAt(1);
						if (next == 'O') otpType.append("OTP ");
						if (next == 'M') otpType.append("EMAIL ");
						if (next == 'I') otpType.append("PIN ");
						if (next == 'S') otpType.append("SMS ");
						if (next == 'Z' && challenge.getAdditionalData() == null) {
							Collection<UserCredentialChallenge> ucch = new RemoteServiceLocator()
									.getPushAuthenticationService()
									.sendPushAuthentication(challenge.getUser().getUserName(),
											idp.getHostName(), text);
							if (!ucch.isEmpty())
								challenge.setAdditionalData(ucch.iterator().next());
						}
					}
				}
			}
			if (otpType.length() > 0 ) {
				challenge.setOtpHandler(otpType.toString());
				challenge.setCardNumber(null);
				challenge.setCell(null);
				ServiceLocator.instance().getOTPValidationService().selectToken(challenge);
				if (challenge.getCardNumber() == null) {
					if (challenge.getAdditionalData() == null)
						throw new InternalErrorException("The user "+challenge.getUser().getUserName()+" needs a multi-factor token ("+otpType.toString().trim()+")");
					else {
						challenge.setOtpHandler("");
						challenge.setCardNumber("");
						challenge.setCell("");
					}
				}
			}
			return accepted;
		}
		else
			return true;
	}

}
