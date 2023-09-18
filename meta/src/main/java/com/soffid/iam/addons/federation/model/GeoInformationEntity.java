package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.iam.addons.federation.api.GeoInformation;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.DaoFinder;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Index;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SCF_GEOIP")
@Depends({GeoInformation.class})
public class GeoInformationEntity {
	@Identifier
	@Column(name = "GEO_ID")
	Long id;
	

	@Column(name = "GEO_IP", length = 40)
	String ip;
	
	@Column(name = "GEO_DATE")
	Date date;
	
	@Nullable
	@Column(name = "GEO_COUNTRY", length = 2)
	String country;
	
	@Nullable
	@Column(name = "GEO_COUDIV", length = 100)
	String countryDivision1;
	
	@Nullable
	@Column(name = "GEO_COUDI2", length = 100)
	String countryDivision2;
	
	@Nullable
	@Column(name = "GEO_CITY", length = 100)
	String city;
	
	@Nullable
	@Column(name = "GEO_LATITU")
	Double latitude;
	
	@Nullable
	@Column(name = "GEO_LONGIT")
	Double longitude;
	
	
	@Nullable
	@Column(name = "GEO_ACCURA")
	Double accuracy;
	
	@Nullable
	@Column(name = "GEO_DOMAIN", length = 150)
	String domain;
	
	@Nullable
	@Column(name = "GEO_ISP", length = 150)
	String isp;
	
	@Nullable 
	@Column(name = "GEO_USETYP", length = 50)
	String userType;
	
	@Nullable
	@Column(name = "GEO_ANONYM")
	Double anonymous;
	
	@Column(name = "GEO_TEN_ID")
	TenantEntity tenant;
	
	@DaoFinder
	public GeoInformationEntity findByIp(String ip) {return null;}
}

@Index (columns = {"GEO_TEN_ID", "GEO_IP"}, entity = GeoInformationEntity.class, name = "SCF_GEOIP_UK")
class GeoInformationEntityUniqueKey {
	
}