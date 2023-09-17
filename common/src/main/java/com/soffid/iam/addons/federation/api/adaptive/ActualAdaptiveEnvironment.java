package com.soffid.iam.addons.federation.api.adaptive;

import java.io.IOException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.User;

import es.caib.seycon.ng.exception.InternalErrorException;

public class ActualAdaptiveEnvironment extends AdaptiveEnvironment {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private String sourceIp;
	private User user;
	private String hostId;
	private int failuresForSameIp;
	private double failuresRatio;
	private String identityProvider;
	private String serviceProvider;
	private boolean deviceCertificate;
	
	private Collection<UserCredentialType> tokens;

	private Collection<String> otps;
	
	public ActualAdaptiveEnvironment(User user, String sourceIp, String hostId, boolean deviceCertificate) throws IOException, InternalErrorException {
		this.user = user;
		this.sourceIp = sourceIp;
		this.hostId = hostId;
		this.deviceCertificate = deviceCertificate;
	}

	@Override
	public boolean newDevice() throws InternalErrorException {
		if (hostId == null || user == null)
			return true;
		Date last = getService().getLastLogon(user.getId(), hostId);
		return last == null;
	}

	public Host remoteHost() throws InternalErrorException {
		return service.findHostBySerialNumber(hostId);
	}

	@Override
	public int failuresForSameIp() {
		return failuresForSameIp;
	}

	@Override
	public int failuresForSameUser() throws InternalErrorException {
		if (user == null)
			return 0;
		long l = getService().getUserFailures(user.getId());
		return l >= Integer.MAX_VALUE ? Integer.MAX_VALUE: (int) l; 
	}

	@Override
	public long secondsSinceLastFail() throws InternalErrorException {
		if (user == null)
			return 0;
		Date d = getService().getLastFailedAttempt(user.getId());
		return d == null  ? 0: (d.getTime() - System.currentTimeMillis())/1000L;
	}

	@Override
	public double failuresRatio() {
		return failuresRatio;
	}

	@Override
	public String sourceCountry() throws InternalErrorException {
		return getService().getCountryForIp(sourceIp);
	}

	@Override
	public String ipAddress() {
		return sourceIp;
	}

	@Override
	public boolean sameCountry() throws InternalErrorException {
		if ( user == null )
			return true;
		String lastCountry = getService().getLastCountry(user.getId());
		if ( lastCountry == null )
			return true;
		else
			return lastCountry.equals(getService().getCountryForIp(sourceIp));
	}

	@Override
	public int daysSinceLastLogon() throws InternalErrorException {
		if (user == null)
			return 0;
		Date lastLogon = getService().getLastLogon(user.getId());
		if (lastLogon == null)
			return 3650;
		
		long days = System.currentTimeMillis() - lastLogon.getTime();
		return (int) (days / 1000 * 60 * 60 * 24);
	}

//	@Override
//	public int daysSinceLastCompatibleLogon() {
//		// TODO Auto-generated method stub
//		return super.daysSinceLastCompatibleLogon();
//	}

	@Override
	public String serviceProvider() {
		return serviceProvider;
	}

	@Override
	public String identityProvider() {
		return identityProvider;
	}

	public String getSourceIp() {
		return sourceIp;
	}

	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public String getHostId() {
		return hostId;
	}

	public void setHostId(String hostId) {
		this.hostId = hostId;
	}

	public int getFailuresForSameIp() {
		return failuresForSameIp;
	}

	public void setFailuresForSameIp(int failuresForSameIp) {
		this.failuresForSameIp = failuresForSameIp;
	}

	public double getFailuresRatio() {
		return failuresRatio;
	}

	public void setFailuresRatio(double failuresRatio) {
		this.failuresRatio = failuresRatio;
	}

	public String getIdentityProvider() {
		return identityProvider;
	}

	public void setIdentityProvider(String identityProvider) {
		this.identityProvider = identityProvider;
	}

	public String getServiceProvider() {
		return serviceProvider;
	}

	public void setServiceProvider(String serviceProvider) {
		this.serviceProvider = serviceProvider;
	}

	@Override
	public User user() {
		return user;
	}

	@Override
	public boolean hasFidoToken() {
		if (user == null)
			return false;
		
		loadTokens();
		return tokens.contains(UserCredentialType.FIDO);
	}

	@Override
	public boolean hasCertificate() {
		if (user == null)
			return false;
		
		loadTokens();
		return tokens.contains(UserCredentialType.CERT);
	}

	private void loadTokens() {
		if (tokens == null) {
			try {
				tokens = getService().getEnabledCredentials(user.getId());
			} catch (InternalErrorException e1) {
				throw new RuntimeException(e1);
			}
		}
	}

	private void loadOtps() {
		if (otps == null) {
			try {
				otps = getService().getEnabledOtps(user.getId());
			} catch (InternalErrorException e1) {
				throw new RuntimeException(e1);
			}
		}
	}

	@Override
	public boolean hasPushToken() {
		if (user == null)
			return false;
		loadTokens();
		return tokens.contains(UserCredentialType.PUSH);
	}

	@Override
	public boolean hasOtpTotp() {
		if (user == null)
			return false;
		loadOtps();
		return otps.contains("TOTP");
	}

	@Override
	public boolean hasOtpHotp() {
		if (user == null)
			return false;
		loadOtps();
		return otps.contains("HOTP");
	}

	@Override
	public boolean hasOtpSms() {
		if (user == null)
			return false;
		loadOtps();
		return otps.contains("SMS");
	}

	@Override
	public boolean hasOtpPin() {
		if (user == null)
			return false;
		loadOtps();
		return otps.contains("PIN");
	}

	@Override
	public boolean hasOtpMail() {
		if (user == null)
			return false;
		loadOtps();
		return otps.contains("EMAIL");
	}

	@Override
	public boolean deviceCertificate() throws InternalErrorException {
		return deviceCertificate;
	}

}
