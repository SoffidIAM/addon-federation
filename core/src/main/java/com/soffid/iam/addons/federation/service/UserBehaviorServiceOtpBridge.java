package com.soffid.iam.addons.federation.service;

import java.util.Calendar;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.service.OtpService;
import com.soffid.iam.model.UserEntity;

public class UserBehaviorServiceOtpBridge {
	protected Collection<String> getEnabledOtps(String userName) throws Exception {
		Set<String> types = new HashSet<>();
		OtpService otpService = (OtpService) com.soffid.iam.ServiceLocator.instance().getService(OtpService.SERVICE_NAME);
		for (OtpDevice cred: otpService.findUserDevices(userName)) {
			if (cred.getStatus() == OtpStatus.VALIDATED) {
				types.add(cred.getType().toString());
			}
		}
		return types;
	}

}
