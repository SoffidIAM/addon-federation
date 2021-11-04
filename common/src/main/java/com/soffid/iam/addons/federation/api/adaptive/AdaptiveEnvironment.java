package com.soffid.iam.addons.federation.api.adaptive;

import java.io.Serializable;
import java.util.Calendar;

import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.api.User;

import es.caib.seycon.ng.exception.InternalErrorException;

public class AdaptiveEnvironment implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected transient UserBehaviorService service;
	
	public boolean newDevice() throws InternalErrorException {
		return true;
	}
	public int failuresForSameIp() {
		return 0;
	}
	public long secondsSinceLastFail() throws InternalErrorException {
		return 0;
	}
	public int failuresForSameUser() throws InternalErrorException {
		return 0;
	}
	public double failuresRatio() {
		return 0.0;
	}
	public String sourceCountry() throws InternalErrorException {
		return "";
	}
	public String ipAddress() {
		return "";
	}
	public boolean sameCountry () throws InternalErrorException {
		return false;
	}
	public int dayOfWeek() {
		return Calendar.getInstance().get(Calendar.DAY_OF_WEEK);
	}
	
	public int hour () {
		return Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
	}

	public int minute () {
		return Calendar.getInstance().get(Calendar.MINUTE);
	}
	
	public int daysSinceLastLogon () throws InternalErrorException
	{
		return 0;
	}
	
	public int daysSinceLastLogonFromSameHost ()
	{
		return 0;
	}
	
	
	public User user() {
		return null;
	}
	
//	public int daysSinceLastCompatibleLogon()
//	{
//		return 0;
//	}
	
	public String serviceProvider()
	{
		return "";
	}
	public String identityProvider()
	{
		return "";
	}
	public UserBehaviorService getService() {
		return service;
	}
	public void setService(UserBehaviorService service) {
		this.service = service;
	}
}
