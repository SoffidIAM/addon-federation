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
import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.addons.federation.common.AuthenticationMethod;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.UserBehaviorEntity;
import com.soffid.iam.addons.otp.service.OtpService;
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
				log.warn("Cannot read GeoIP database "+f+". Upload it from https://dev.maxmind.com/geoip/geoip2/geolite2/");
				return "?";
			}
			reader = new DatabaseReader.Builder(new File(f)).build();
		}


		InetAddress ipAddress = InetAddress.getByName(ip);

		// Replace "city" with the appropriate method for your database, e.g.,
		// "country".
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
	protected String handleRegisterHost(String hostIp) throws Exception {
		String hostName = hostIp + "_" + System.currentTimeMillis();
		byte b[] = new byte[24];
		SecureRandom r = new SecureRandom();
		r.nextBytes(b);
		String serialNumber = System.currentTimeMillis()+"_"+Base64.encodeBytes(b);
		getNetworkService().registerDynamicIP(hostName, hostIp, serialNumber);
		return serialNumber;
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
		if (hostId != null)
		{
			setValue (userId, "lastLogon_"+hostId, now);
		}
		setValue (userId, "failures", "0");
		setValue (userId, "lastFail", "");
		setValue (userId, "lastLogon", now);
		String country = handleGetCountryForIp(hostIp);
		setValue (userId, "lastCountry", country);
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
}
