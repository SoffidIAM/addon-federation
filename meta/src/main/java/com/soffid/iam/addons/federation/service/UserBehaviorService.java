package com.soffid.iam.addons.federation.service;

import java.util.Date;

import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.model.UserBehaviorEntity;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.Service;

import es.caib.seycon.ng.model.UsuariEntity;
import es.caib.seycon.ng.servei.AccountService;
import es.caib.seycon.ng.servei.DispatcherService;
import es.caib.seycon.ng.servei.XarxaService;

@Service(serverPath = "/seycon/UserBehaviorService",
	serverRole="agent")
@Depends({UserBehaviorEntity.class, 
		UsuariEntity.class,
		XarxaService.class})
public class UserBehaviorService {
	public String getCountryForIp(String ip) { return null; }
	public String getLastCountry(Long userId) {return null; }
	
	public long getUserFailures (Long userId) {return 0L;}
	public void setUserFailures (Long userId, long failures) {};
	
	public Date getLastFailedAttempt (Long userId) {return null;}
	public Date getLastLogon (Long userId) {return null;}
	public Date getLastLogon (Long userId, String hostId) {return null;}
	public void registerLogon (Long userId, String hostIp, @Nullable String hostId) {}
	public String registerHost (String hostIp) {return null;}
	
	public AuthenticationMethod getAuthenticationMethod ( FederationMember fm, AdaptiveEnvironment env) {return null;}
	
	public boolean isLocked(Long userId) {return false;}
}
