package com.soffid.iam.addons.federation.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.soffid.iam.addons.federation.api.GeoInformation;
import com.soffid.iam.addons.federation.model.GeoInformationEntity;
import com.soffid.iam.utils.ConfigurationCache;

import es.caib.seycon.ng.exception.InternalErrorException;

public class GeoInformationServiceImpl extends GeoInformationServiceBase {
	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected GeoInformation handleGetGeoInformation(String ip) throws Exception {
		String user = ConfigurationCache.getProperty("maxmind.account");
		String password = ConfigurationCache.getProperty("maxmind.license");
		String url = ConfigurationCache.getProperty("maxmind.url");
		String cache = ConfigurationCache.getProperty("maxmind.cache");
		int cacheDays = 30;
		try {
			cacheDays = Integer.parseInt(cache);
		} catch (Exception e) {}
		
		if (url != null && user != null && password != null) {
			if (isPrivate(ip)) {
				return generatePrivateRecord (ip);
			}
			GeoInformationEntity entity = getGeoInformationEntityDao().findByIp(ip);
			if (entity == null) {
				entity = getGeoInformationEntityDao().newGeoInformationEntity();
				try {
					fetch (ip, user,password, url, entity);
					getGeoInformationEntityDao().create(entity);
				} catch (Exception e) {
					log.warn("Error fetching information for IP "+ip, e);
					return generatePrivateRecord(ip);
				}
			} else if (isExpired(entity, cacheDays)) {
				try {
					fetch (ip, user,password, url, entity);
					getGeoInformationEntityDao().update(entity);
				} catch (Exception e) {
					log.warn("Error fetching information for IP "+ip, e);
				}
			}
			return getGeoInformationEntityDao().toGeoInformation(entity);
		}
		else
			return generatePrivateRecord(ip);
	}

	private void fetch(String ip, String user, String password, String urlString, GeoInformationEntity entity) throws IOException {
		if (!urlString.endsWith("/"))
			urlString += "/";
		urlString += URLEncoder.encode(ip, StandardCharsets.UTF_8);
		URL url = new URL(urlString);
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setDoOutput(false);
		conn.setDoInput(true);
		conn.setRequestMethod("GET");
		conn.addRequestProperty("Authorization", 
				"Basic "+Base64.getEncoder().encodeToString(
						(URLEncoder.encode(user, StandardCharsets.UTF_8)
								+":"
								+URLEncoder.encode(password, StandardCharsets.UTF_8))
						.getBytes(StandardCharsets.UTF_8)));
		conn.connect();
		if (conn.getResponseCode() >= 200 && conn.getResponseCode() < 400) {
			InputStream in = conn.getInputStream();
			JSONObject response = new JSONObject(new JSONTokener(in));
			parse (response, entity);
			entity.setIp(ip);
			entity.setDate(new Date());
			in.close();
			conn.disconnect();
		} else {
			InputStream in = conn.getInputStream();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			for (int read = in.read(); read >= 0; read = in.read())
				out.write(read);
			out.close();
			in.close();
			conn.disconnect();
			throw new IOException("Error getting response from "+urlString
					+": HTTP/"+conn.getResponseCode()+"\n"
					+out.toString(StandardCharsets.UTF_8));
		}
	}

	private void parse(JSONObject response, GeoInformationEntity entity) {
		JSONObject location = response.optJSONObject("location");
		if (location == null) {
			entity.setAccuracy(null);
			entity.setLatitude(null);
			entity.setLongitude(null);
		} else {
			entity.setAccuracy(location.optDouble("accuracy_radius"));
			entity.setLatitude(location.optDouble("latitude"));
			entity.setLongitude(location.optDouble("longitude"));
		}
		JSONObject traits = response.optJSONObject("traits");
		if (traits == null) {
			entity.setAnonymous(null);
			entity.setDomain(null);
			entity.setId(null);
			entity.setUserType(null);
		} else {
			if (traits.optBoolean("is_anonymous"))
				entity.setAnonymous(1.0);
			else if (traits.optBoolean("is_anonymous_vpn")) 
				entity.setAnonymous(1.0);
			else if (traits.optBoolean("is_hosting_provider"))
				entity.setAnonymous(0.25);
			else if (traits.optBoolean("is_public_proxy"))
				entity.setAnonymous(0.75);
			else if (traits.optBoolean("is_residential_proxy"))
				entity.setAnonymous(1.0);
			else if (traits.optBoolean("is_tor_exit_node"))
				entity.setAnonymous(1.0);
			else
				entity.setAnonymous(0.0);
			entity.setDomain(traits.optString("domain"));
			entity.setIsp(traits.optString("isp"));
			entity.setUserType(traits.optString("user_type"));
		}
		JSONObject city = response.optJSONObject("city");
		if (city == null) {
			entity.setCity(null);
		} else {
			entity.setCity(city.getJSONObject("names").optString("en"));
		}
		JSONObject country = response.optJSONObject("country");
		if (country == null) {
			entity.setCountry(null);
		} else {
			entity.setCountry(country.optString("iso_code"));
		}
		JSONArray subdivisions = response.optJSONArray("subdivisions");
		if (subdivisions != null && subdivisions.length() > 0) {
			entity.setCountryDivision1(subdivisions
					.getJSONObject(0)
					.getJSONObject("names")
					.optString("en"));
		}
		if (subdivisions != null && subdivisions.length() > 1) {
			entity.setCountryDivision2(subdivisions
					.getJSONObject(1)
					.getJSONObject("names")
					.optString("en"));
		}
	}

	private GeoInformation generatePrivateRecord(String ip) {
		GeoInformation g = new GeoInformation();
		g.setIp(ip);
		g.setAnonymous(0.0);
		g.setUserType("private");
		return g;
	}

	private boolean isPrivate(String ip) throws UnknownHostException {
		InetAddress inet = InetAddress.getByName(ip);
		byte[] data = inet.getAddress();
		if (data.length == 4) // ip4
		{
			if (data[0] == 10) return true;
			if (data[0] == 172 - 256 && (data[1] & 0xf0) == 16) return true;
			if (data[0] == 192 - 256 && data[1] == 168 - 256) return true;
			if (data[0] == 127 - 256) return true; // Loopback
			return false;
		}
		else
		{
			if (data[0] == 0xfd - 256) return true;
			if (data[0] == 0xfe - 256) return true;
			if (data[0] == 0 &&
					data[1] == 0 &&
					data[2] == 0 &&
					data[3] == 0 &&
					data[4] == 0 &&
					data[5] == 0 &&
					data[6] == 0 &&
					data[7] == 1) return true; // Loopback
			return false;
		}
	}

	private boolean isExpired(GeoInformationEntity entity, int cacheDays) {
		long expire = entity.getDate().getTime() + (long) cacheDays * 24L * 60L * 60L * 1000L;
		return expire < System.currentTimeMillis();
	}

}
