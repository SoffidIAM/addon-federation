package com.soffid.iam.addons.federation.service;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.CountryResponse;
import com.soffid.iam.addons.federation.api.GeoInformation;
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderEntity;
import com.soffid.iam.addons.federation.model.UserBehaviorEntity;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.impl.IssueHelper;
import com.soffid.iam.addons.otp.service.OtpService;
import com.soffid.iam.api.Audit;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.User;
import com.soffid.iam.model.AccountEntity;
import com.soffid.iam.model.SystemEntity;
import com.soffid.iam.model.UserAccountEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.sync.engine.extobj.AttributeReferenceParser;
import com.soffid.iam.sync.engine.extobj.ExtensibleObjectNamespace;
import com.soffid.iam.utils.ConfigurationCache;

import bsh.EnvironmentNamespace;
import bsh.EvalError;
import bsh.Interpreter;
import bsh.NameSpace;
import bsh.Primitive;
import bsh.TargetError;
import es.caib.seycon.ng.comu.Maquina;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class UserBehaviorServiceImpl extends UserBehaviorServiceBase {
	Log log = LogFactory.getLog(getClass());
	private DatabaseReader reader = null;
	long readerTimestamp = 0;

	@Override
	protected String handleGetCountryForIp(String ip) throws Exception {
		if (reader == null || readerTimestamp < System.currentTimeMillis() - 120000L) // 2 minutes
		{
			String f = ConfigurationCache.getMasterProperty("soffid.geoip2.database");
			if ( f == null)
				f = "/usr/share/GeoIP/GeoLite2-Country.mmdb";
			if ( ! new File(f).canRead())
			{
				GeoInformation geo = getGeoInformationService().getGeoInformation(ip);
				if (geo.getCountry() != null)
					return geo.getCountry();
				log.warn("Cannot read GeoIP database "+f+". Upload it from https://dev.maxmind.com/geoip/geoip2/geolite2/");
				return "?";
			}
			reader = new DatabaseReader.Builder(new File(f)).build();
		}


		InetAddress ipAddress = InetAddress.getByName(ip);

		try { 
			CountryResponse response = reader.country(ipAddress);
			if (response == null || response.getCountry() == null || response.getCountry().getIsoCode() == null)
				return null;
			else
				return response.getCountry().getIsoCode();
		} catch (AddressNotFoundException e) {
			log.info(e.getMessage());
			return "??";
		}

	}

	@Override
	protected String handleGetLastCountry(Long userId) throws Exception {
		return getValue (userId, "lastCountry");
	}

	@Override
	protected long handleGetUserFailures(Long userId) throws Exception {
		String s = getValue(userId, "failures");
		if (s == null)
			return 0;
		else
			return Long.parseLong(s);
	}

	@Override
	protected void handleSetUserFailures(Long userId, long failures) throws Exception {
		setValue (userId, "failures", Long.toString(failures));
		setValue (userId, "lastFail", Long.toString(System.currentTimeMillis()));
	}

	@Override
	protected String handleRegisterHost(String hostIp, String device, String browser, String os, String cpu) throws Exception {
		String hostName = hostIp + "_" + System.currentTimeMillis();
		byte b[] = new byte[24];
		SecureRandom r = new SecureRandom();
		r.nextBytes(b);
		String serialNumber = System.currentTimeMillis()+"_"+Base64.encodeBytes(b);
		Host h = getNetworkService().registerDynamicIP(hostName, hostIp, serialNumber);
		h.getAttributes().put("device", device);
		h.getAttributes().put("detectedOs", os);
		h.getAttributes().put("browser", browser);
		h.getAttributes().put("cpu", cpu);
		h.setLastSeen(Calendar.getInstance());
		updateOs(h, device, os);
		getNetworkService().update(h);
		return serialNumber;
	}

	private void updateOs(Host h, String device, String os) throws InternalErrorException {
		if (h.getOs() == null)
			updateOs(h, "ALT");
		if (os.toLowerCase().contains("windows")) {
			if ("Desktop".equalsIgnoreCase(device)) 
				updateOs(h, "WNT");
			else
				updateOs(h, "NTS");
		}
		if (os.toLowerCase().contains("linux")) {
			updateOs(h, "LIN");
		}
	}

	private void updateOs(Host h, String string) throws InternalErrorException {
		if (getNetworkService().findOSTypeByName(string) != null)
			h.setOs(string);
	}

	@Override
	protected void handleUpdateHost(String hostId, String hostIp, String device, String browser, String os, String cpu) throws Exception {
		Host h = getNetworkService().findHostBySerialNumber(hostId);
		if (h != null) {
			h.setLastSeen(Calendar.getInstance());
			h.getAttributes().put("device", device);
			h.getAttributes().put("detectedOs", os);
			h.getAttributes().put("browser", browser);
			h.getAttributes().put("cpu", cpu);
			updateOs(h, device, os);
			getNetworkService().update(h);
		}
	}

	@Override
	protected Date handleGetLastLogon(Long userId) throws Exception {
		String s = getValue(userId, "lastLogon");
		if (s == null)
			return null;
		else
			return new Date( Long.parseLong( s ));
	}

	@Override
	protected Date handleGetLastFailedAttempt(Long userId) throws Exception {
		String s = getValue(userId, "lastFail");
		if (s == null || s.trim().isEmpty())
			return null;
		else
			return new Date( Long.parseLong( s ));
	}

	@Override
	protected Date handleGetLastLogon(Long userId, String hostId) throws Exception {
		String s = getValue(userId, "lastLogon_"+hostId);
		if (s == null)
			return null;
		else
			return new Date( Long.parseLong( s ));
	}

	@Override
	protected void handleRegisterLogon(Long userId, String hostIp, String hostId) throws Exception {
		String now = Long.toString( System.currentTimeMillis() );
		setValue (userId, "failures", "0");
		setValue (userId, "lastFail", "");
		setValue (userId, "lastLogon", now);

		String country = handleGetCountryForIp(hostIp);
		if (country != null && !country.equals("??")) {
			String lastCountry = getValue(userId, "lastCountry");
			if (lastCountry != null && !lastCountry.equals(country))
			{
				try {
					IssueHelper.fromDifferentCountry(userId, country);
				} catch (Error e) {
					// Old syncserver version
				}
			}
			setValue (userId, "lastCountry", country);
			
		}
		
		GeoInformation geo = getGeoInformationService().getGeoInformation(hostIp);
		if (geo != null && geo.getLatitude() != null && geo.getLongitude() != null) {
			setValue(userId, "longitude", geo.getLongitude().toString());
			setValue(userId, "latitude", geo.getLatitude().toString());
			setValue(userId, "pos_accuracy", geo.getAccuracy() == null ? "": geo.getAccuracy().toString());
			setValue(userId, "pos_time", now);
		}
		

		if (hostId != null) {
			String lastLogon = getValue(userId, "lastLogon_"+hostId);
			if (lastLogon == null) {
				try {
					Host host = getNetworkService().findHostBySerialNumber(hostId);
					IssueHelper.fromNewHost(userId, host);				
				} catch (Error e) {
					// Old syncserver version
				}
			}
			setValue (userId, "lastLogon_"+hostId, now);
		}
	}

	protected String getValue (Long userId, String key)
	{
		UserBehaviorEntity e = getUserBehaviorEntityDao().findByUserIdAndKey(userId, key);
		if (e == null)
			return null;
		else
			return e.getValue();
	}
	
	protected void setValue (Long userId, String key, String value)
	{
		UserBehaviorEntity e = getUserBehaviorEntityDao().findByUserIdAndKey(userId, key);
		if (e == null)
		{
			e = getUserBehaviorEntityDao().newUserBehaviorEntity();
			e.setUserId(userId);
			e.setKey(key);
			e.setValue(value);
			getUserBehaviorEntityDao().create(e);
		} else {
			e.setValue(value);
			getUserBehaviorEntityDao().update(e);
		}
	}

	public AuthenticationMethod handleGetAuthenticationMethod(FederationMember fm, AdaptiveEnvironment env) throws InternalErrorException {
		env.setService(this);
		env.setGeoInformationService(getGeoInformationService());
		
		for (AuthenticationMethod method: fm.getExtendedAuthenticationMethods())
		{
			if (matchesCondition (method, env))
			{
				log.info ("Applying adaptive profile "+method.getDescription()+" for " + 
						(env.user() == null ? "unknown user": env.user().getUserName()));
				return method;
			}
		}
		AuthenticationMethod m = new AuthenticationMethod();
		m.setAlwaysAskForCredentials(fm.getAlwaysAskForCredentials());
		m.setDescription("Default");
		m.setAuthenticationMethods(fm.getAuthenticationMethods());
		return m;
	}

	private boolean matchesCondition(AuthenticationMethod method, AdaptiveEnvironment env) throws InternalErrorException {
		Interpreter interpret = new Interpreter();
		NameSpace ns = interpret.getNameSpace();

		EnvironmentNamespace newNs = new EnvironmentNamespace(env);
		
		try {
			Object result = interpret.eval(method.getExpression(), newNs);
			if (result instanceof Primitive)
			{
				result = ((Primitive)result).getValue();
			}
			return Boolean.TRUE.equals(result);
		} catch (TargetError e) {
			log.warn("Error evaluating rule "+method.getDescription()+"\n"+method.getExpression()+"\nMessage:"+
					e.getTarget().getMessage(),
					e.getTarget());
			return false;
		} catch (EvalError e) {
			String msg;
			try {
				msg = e.getMessage() + "[ "+ e.getErrorText()+"] ";
			} catch (Exception e2) {
				msg = e.getMessage();
			}
			log.warn("Error evaluating rule "+method.getDescription()+"\n"+method.getExpression()+"\nMessage:"+msg);
			return false;
		}
	}

	@Override
	protected boolean handleIsLocked(Long userId) throws Exception {
		long f = handleGetUserFailures(userId);
		if (f >= 3) {
			Date d = handleGetLastFailedAttempt(userId);
			if (d != null && System.currentTimeMillis() - d.getTime() < 60000 ) // 10 minutes lock
			{
				UserEntity user = getUserEntityDao().load(userId);
				if (user == null)
					return true;
				for (UserAccountEntity userAccount: user.getAccounts()) {
					Date d2 = userAccount.getAccount().getLastPasswordSet();
					if (d2 != null && d2.after(d))
						return false;
				}
				return true;
			}
		}
		return false;
	}

	@Override
	protected Collection<UserCredentialType> handleGetEnabledCredentials(Long userId) throws Exception {
		UserEntity u = getUserEntityDao().load(userId);
		Set<UserCredentialType> types = new HashSet<>();
		for (UserCredential cred: getUserCredentialService().findUserCredentials(u.getUserName())) {
			if (cred.getExpirationDate() == null || Calendar.getInstance().before(cred.getExpirationDate())) {
				types.add(cred.getType());
			}
		}
		return types;
	}

	@Override
	protected Collection<String> handleGetEnabledOtps(Long userId) throws Exception {
		UserEntity u = getUserEntityDao().load(userId);
		try {
			return new UserBehaviorServiceOtpBridge().getEnabledOtps(u.getUserName());
		} catch (Error th) {
			return new HashSet<String>();
		}
	}

	@Override
	protected PasswordValidation handleValidatePassword(FederationMember federationMember, String account, Password p)
			throws Exception {
		FederationMemberEntity fme = getFederationMemberEntityDao().load(federationMember.getId());
		if (fme instanceof ServiceProviderEntity) {
			ServiceProviderEntity sp = (ServiceProviderEntity) fme;
			SystemEntity system = sp.getSystem();
			if (system == null) {
				system = getSystemEntityDao().findSoffidSystem();
			}
			AccountEntity acc = getAccountEntityDao().findByNameAndSystem(account, system.getName());
			if (acc != null && !acc.isDisabled()) {
				return getInternalPasswordService().checkAccountPassword(acc, p, true, false);
			}
		}
		return PasswordValidation.PASSWORD_WRONG;
	}

	@Override
	protected void handleChangePassword(FederationMember federationMember, String account, Password oldPass, Password newPass)
			throws Exception {
		if (handleValidatePassword(federationMember, account, oldPass) != PasswordValidation.PASSWORD_WRONG) {
			getInternalPasswordService().storeAndSynchronizeAccountPassword(null, newPass, false, null);
		} else {
			throw new InternalErrorException("Wrong password");
		}
	}

	@Override
	protected Host handleFindHostBySerialNumber (String serialNumber) throws InternalErrorException {
		return getNetworkService().findHostBySerialNumber(serialNumber);
	}

	@Override
	protected Double handleGetDisplacement(User user, String newIp) throws Exception {
		GeoInformation geo = getGeoInformationService().getGeoInformation(newIp);
		if (geo.getLatitude() == null || geo.getLongitude() == null)
			return null;
		double oldLatitude = Double.parseDouble( getValue(user.getId(), "latitude") );
		double oldLongitude = Double.parseDouble(getValue(user.getId(), "longitude") );
		String oldAccuracyString = getValue(user.getId(), "pos_accuracy");
		Double oldAccuracy = oldAccuracyString == null || oldAccuracyString.isBlank() ?
				0: Double.parseDouble(oldAccuracyString);
		
		double difLatitudeRad = (geo.getLatitude().doubleValue() - oldLatitude) * Math.PI / 180.0;
		double difLongitudeRad = (geo.getLongitude().doubleValue() - oldLongitude) * Math.PI / 180.0;
		double dfs = Math.sin(difLatitudeRad / 2);
		double dfs2 = Math.sin(difLongitudeRad/2);
		double a = dfs * dfs +
				Math.cos(geo.getLatitude() * Math.PI / 180.0) *
				Math.cos(oldLatitude * Math.PI / 180.0) *
				dfs2 * dfs2;
		double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
		c = Math.abs(6378.0 * c);
		if (oldAccuracy != null)
			c = c - oldAccuracy.doubleValue();
		if (geo.getAccuracy() != null)
			c = c - geo.getAccuracy();
		if (c < 0) c = 0;
		return c;
	}

	@Override
	protected Double handleGetDisplacementSpeed(User user, String newIp) throws Exception {
		Double dis = handleGetDisplacement(user, newIp);
		if (dis == null)
			return null;
		long oldTime = Long.parseLong(getValue(user.getId(), "pos_time"));
		return dis.doubleValue() / (System.currentTimeMillis() - oldTime) 
				/ 60.0 * 60.0 * 1000.0;
	}
}
