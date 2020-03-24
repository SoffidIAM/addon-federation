package com.soffid.iam.addons.federation.test;

import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import com.soffid.iam.utils.ConfigurationCache;

public class GeoTest {
	public static void main(String args[]) throws IOException, GeoIp2Exception {
		String f = "/usr/share/GeoIP/GeoLite2-Country.mmdb";
		DatabaseReader reader = new DatabaseReader.Builder(new File(f)).build();

		InetAddress ipAddress = InetAddress.getByName("188.165.133.107");

		// Replace "city" with the appropriate method for your database, e.g.,
		// "country".
		CountryResponse response = reader.country(ipAddress);

		System.out.println (response.getCountry().getIsoCode());
		System.out.println (response.getCountry().getName());

	}
}
