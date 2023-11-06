package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class GeoInformation {
	@Column(name = "GEO_IP", length = 40)
	String ip;
	
	@Column(name = "GEO_DATE")
	Date date;
	
	@Nullable
	String country;
	
	@Nullable
	String countryDivision1;
	
	@Nullable
	String countryDivision2;
	
	@Nullable
	String city;
	
	@Nullable
	Double latitude;
	
	@Nullable
	Double longitude;
	
	
	@Nullable
	Double accuracy;
	
	@Nullable
	String domain;
	
	@Nullable
	String isp;
	
	@Nullable 
	String userType;
	
	@Nullable
	Double anonymous;
	

}
