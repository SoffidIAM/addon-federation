package com.soffid.iam.addons.federation.api.adaptive;

import java.io.Serializable;
import java.util.Calendar;

import com.soffid.iam.addons.federation.api.GeoInformation;
import com.soffid.iam.addons.federation.service.UserBehaviorService;
import com.soffid.iam.addons.federation.service.GeoInformationService;
import com.soffid.iam.api.Host;
import com.soffid.iam.api.User;

import es.caib.seycon.ng.exception.InternalErrorException;

public class AdaptiveEnvironment implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected transient UserBehaviorService service;
	protected GeoInformationService geoService;
	
	public boolean newDevice() throws InternalErrorException {
		return true;
	}
	
	public Host remoteHost() throws InternalErrorException {
		return new Host();
	}
	
	public boolean deviceCertificate() throws InternalErrorException {
		return false;
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
	
	public boolean hasOtp() { return hasOtpHotp() || hasOtpMail() || hasOtpPin() || hasOtpSms() || hasOtpTotp(); }
	
	public boolean hasToken() {return hasFidoToken() || hasCertificate() || hasPushToken(); }
	
	public boolean hasFidoToken() {return false;}
	
	public boolean hasCertificate() {return false;}
	
	public boolean hasOtpTotp() {return false;}
	
	public boolean hasOtpHotp() {return false;}
	
	public boolean hasOtpSms() {return false;}
	
	public boolean hasOtpPin() {return false;}
	
	public boolean hasOtpMail() {return false;}
	
	public boolean hasPushToken() {return false;}

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
	
	public GeoInformationService getGeoInformationService() {
		return geoService;
	}
	public void setGeoInformationService(GeoInformationService service) {
		this.geoService = service;
	}

	public GeoInformation geoInformation() throws InternalErrorException { 
		return new GeoInformation();
	};
	
	public Double displacementSpeed() throws InternalErrorException {
		return null;
	}

	public Double displacement() throws InternalErrorException {
		return null;
	}
}
