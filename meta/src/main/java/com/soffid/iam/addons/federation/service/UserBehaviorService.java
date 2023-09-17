package com.soffid.iam.addons.federation.service;

import java.util.Collection;
import java.util.Date;

import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.UserBehaviorEntity;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.PasswordValidation;
import es.caib.seycon.ng.model.AccountEntity;
import es.caib.seycon.ng.model.DispatcherEntity;
import es.caib.seycon.ng.model.UsuariEntity;
import es.caib.seycon.ng.servei.AccountService;
import es.caib.seycon.ng.servei.DispatcherService;
import es.caib.seycon.ng.servei.InternalPasswordService;
import es.caib.seycon.ng.servei.XarxaService;

@Service(serverPath = "/seycon/UserBehaviorService",
	serverRole="agent")
@Depends({UserBehaviorEntity.class, 
		UsuariEntity.class,
		XarxaService.class,
		UserCredentialService.class,
		FederationMemberEntity.class,
		AccountEntity.class,
		DispatcherEntity.class,
		InternalPasswordService.class})
public class UserBehaviorService {
	public String getCountryForIp(String ip) { return null; }
	public String getLastCountry(Long userId) {return null; }
	
	public long getUserFailures (Long userId) {return 0L;}
	public void setUserFailures (Long userId, long failures) {};
	
	public Date getLastFailedAttempt (Long userId) {return null;}
	public Date getLastLogon (Long userId) {return null;}
	public Date getLastLogon (Long userId, String hostId) {return null;}
	public void registerLogon (Long userId, String hostIp, @Nullable String hostId) {}
	public String registerHost (String hostIp, @Nullable String device, @Nullable String browser, @Nullable String os, @Nullable String cpu) {return null;}
	public void updateHost (String hostId, String hostIp, @Nullable String device, @Nullable String browser, @Nullable String os, @Nullable String cpu) {}
	public Maquina findHostBySerialNumber (String serialNumber) {return null;}
	
	public AuthenticationMethod getAuthenticationMethod ( FederationMember fm, AdaptiveEnvironment env) {return null;}
	
	public boolean isLocked(Long userId) {return false;}
	
	public Collection<UserCredentialType> getEnabledCredentials(Long userId) {return null;}
	public Collection<String> getEnabledOtps(Long userId) {return null;}

	public PasswordValidation validatePassword(FederationMember federationMember, String account, Password p) { return null; }
	public void changePassword(FederationMember federationMember, String account, Password oldPass, Password newPass) {}
}
