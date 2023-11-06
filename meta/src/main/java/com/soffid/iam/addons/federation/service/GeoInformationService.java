package com.soffid.iam.addons.federation.service;

import com.soffid.iam.addons.federation.api.GeoInformation;
import com.soffid.iam.addons.federation.model.GeoInformationEntity;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Service;

@Service
@Depends({GeoInformationEntity.class})
public class GeoInformationService {
	public GeoInformation getGeoInformation(String ip) {return null;}
}
