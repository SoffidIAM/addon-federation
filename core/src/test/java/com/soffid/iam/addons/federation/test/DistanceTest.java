package com.soffid.iam.addons.federation.test;

import com.soffid.iam.addons.federation.api.GeoInformation;

public class DistanceTest {
	
	public static void main(String args[]) {
		final double RadioTierraKm = 6378.0F;
		double oldLatitude = 39.5701058;
		double oldLongitude = 2.6487098;
		Double oldAccuracy = 0.0;
		GeoInformation geo = new GeoInformation();
		geo.setLatitude(41.3584576);
		geo.setLongitude(2.100455);
		
		double difLatitudeRad = (geo.getLatitude().doubleValue() - oldLatitude) * Math.PI / 180.0;
		double difLongitudeRad = (geo.getLongitude().doubleValue() - oldLongitude) * Math.PI / 180.0;
		double dfs = Math.sin(difLatitudeRad / 2);
		double dfs2 = Math.sin(difLongitudeRad/2);
		double a = dfs * dfs + 
				Math.cos(geo.getLatitude() * Math.PI / 180.0) *
				Math.cos(oldLatitude * Math.PI / 180.0) *
				dfs2 * dfs2;
		double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)) * RadioTierraKm;
		c = Math.abs(c);
		if (oldAccuracy != null)
			c = c - oldAccuracy.doubleValue();
		if (geo.getAccuracy() != null)
			c = c - geo.getAccuracy();
		if (c < 0) c = 0;
		System.out.println(c);
		
	    double lat1rad = Math.toRadians(geo.getLatitude().doubleValue());
	    double lon1rad = Math.toRadians(geo.getLongitude().doubleValue());
	    double lat2rad = Math.toRadians(oldLatitude);
	    double lon2rad = Math.toRadians(oldLongitude);

	    double difLatitud = lat1rad - lat2rad;
	    double difLongitud = lon1rad - lon2rad;

	    a = Math.pow(Math.sin(difLatitud/2), 2) +
	            Math.cos(lat1rad) *
	            Math.cos(lat2rad) *
	            Math.pow(Math.sin(difLongitud/2), 2);
	    c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));

	    double radioTierraKm = 6378.0;
	    double distancia = radioTierraKm * c;
		System.out.println(distancia);
	}
}
