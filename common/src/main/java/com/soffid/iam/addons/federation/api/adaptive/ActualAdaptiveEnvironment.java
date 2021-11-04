package com.soffid.iam.addons.federation.api.adaptive;

import java.io.IOException;
import java.util.Date;

import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
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
	public ActualAdaptiveEnvironment(User user, String sourceIp, String hostId) throws IOException, InternalErrorException {
		this.user = user;
		this.sourceIp = sourceIp;
		this.hostId = hostId;
	}

	@Override
	public boolean newDevice() throws InternalErrorException {
		if (hostId == null)
			return true;
		Date last = getService().getLastLogon(user.getId(), hostId);
		return last != null;
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

}
