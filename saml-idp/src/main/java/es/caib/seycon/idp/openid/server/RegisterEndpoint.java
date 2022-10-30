package es.caib.seycon.idp.openid.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpCookie;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Password;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class RegisterEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		try {
			String clientId = req.getParameter("client_id");
			if (clientId == null || clientId.trim().isEmpty())
			{
				resp.sendError(HttpServletResponse.SC_NOT_FOUND);
			}
			else
			{
				IdpConfig cfg = IdpConfig.getConfig();
				FederationMember fm = cfg.getFederationService().findFederationMemberByClientID(clientId);
				if (fm == null)
				{
					resp.sendError(HttpServletResponse.SC_NOT_FOUND);
				}
				else
				{
					String authentication = req.getHeader("Authorization");
					if (authentication == null || ! authentication.toLowerCase().startsWith("bearer "))
					{
						resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
						resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
						log.warn("Trying to get access without bearer token");
					} else {
						String token = authentication.substring(7);
						if (fm.getRegistrationToken() == null ||  ! fm.getRegistrationToken().validate(token)) {
							resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
							log.warn("Trying to get access with wrong token");
						}
						else
						{
							JSONObject o = generateObject(fm, null, null);
							resp.setStatus(201);
							resp.setContentType("appliaction/json");
							resp.addHeader("Pragma", "no-cache");
							resp.addHeader("Cache-Control", "no-store");
							ServletOutputStream out = resp.getOutputStream();
							out.write(o.toString().getBytes(StandardCharsets.UTF_8));
							out.close();
							
						}
					}
				}
			}
		} catch (InternalErrorException e) {
			log.warn("Error registering client", e);
			buildError(resp, "Error registering client: "+e.getMessage());
		} catch (Throwable e) {
			log.warn("Error registering client", e);
			buildError(resp, "Error registering client");
		}
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");

		String authentication = req.getHeader("Authorization");
		if (authentication == null || ! authentication.toLowerCase().startsWith("bearer "))
		{
			resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
			log.warn("Trying to get access without bearer token");
			return;
		}
		String token = authentication.substring(7);
			
		try {
			int i = token.indexOf(".");
			if (i >= 0) {
				Long id = Long.parseLong( new String ( java.util.Base64.getUrlDecoder().decode(token.substring(0, i)), "UTF-8"));
				FederationMember s = IdpConfig.getConfig().getFederationService().findFederationMemberById(id);
				
				if (s != null && s.getRegistrationToken() != null && s.getRegistrationToken().validate(token)) {
					if (new Date().before(s.getRegistrationTokenExpiration())) {
						JSONObject o = register(s, req);
						resp.setStatus(201);
						resp.setContentType("appliaction/json");
						resp.addHeader("Pragma", "no-cache");
						resp.addHeader("Cache-Control", "no-store");
						ServletOutputStream out = resp.getOutputStream();
						out.write(o.toString().getBytes(StandardCharsets.UTF_8));
						out.close();
						return;
					}
				}
			}
			resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
			log.warn("Trying to get access without bearer token");
		} catch (InternalErrorException e) {
			log.warn("Error registering client", e);
			buildError(resp, "Error registering client: "+e.getMessage());
		} catch (Throwable e) {
			log.warn("Error registering client", e);
			buildError(resp, "Error registering client");
		}
	}

	private JSONObject register(FederationMember s, HttpServletRequest req) throws JSONException, IOException, InternalErrorException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException {
		req.setCharacterEncoding("UTF-8");
		JSONObject o = new JSONObject(new JSONTokener(req.getInputStream()));
		FederationMember fm = new FederationMember(s);
		fm.setId(null);
		FederationService svc = IdpConfig.getConfig().getFederationService();
		int i = 1;
		do {
			fm.setPublicId(s.getPublicId()+"_"+i);
			if (svc.findFederationMemberByPublicId(fm.getPublicId()) == null) break;
			i++;
		} while (true);
		String method = o.optString("token_endpoint_auth_method", null);
		String secret = null;
		fm.setOpenidClientId(fm.getPublicId());
		if (method != null) {
			secret = generateRandom();
			fm.setOpenidSecret(new Digest(secret));
		}
		fm.setName(o.optString("client_name", fm.getPublicId()));
		fm.setServiceProviderType(ServiceProviderType.OPENID_CONNECT);
		List<String> l = new LinkedList<>();
		fillList(l, o.opt("redirect_uris"));
		fillList(l, o.opt("requests_uris"));		
		fm.setOpenidUrl(l);
		fm.setOpenidLogoutUrlFront(o.optString("frontchannel_logout_uri", null));
		fm.setOpenidLogoutUrlBack(o.optString("backchannel_logout_uri", null));
		fm.setDynamicRegistrationServer(s.getPublicId());
		
		fm = svc.create(fm);
		
		String registrationToken = encodeId(fm.getId())
				+"."+generateRandom();
		fm.setRegistrationToken(new Digest(registrationToken));
		
		svc.update(fm);
		
		return generateObject(fm, secret, registrationToken);
	}

	private String encodeId(Long id) {
		String s = java.util.Base64.getUrlEncoder().encodeToString(id.toString().getBytes(StandardCharsets.UTF_8));
		while (s.endsWith("="))
			s = s.substring(0, s.length()-1);
		return s;
	}

	private JSONObject generateObject(FederationMember fm, String secret, String registrationToken) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		IdpConfig cfg = IdpConfig.getConfig();
		FederationMember idp = cfg.getFederationMember();
		
		JSONObject o = new JSONObject();
		o.put("client_id", fm.getOpenidClientId());
		if (secret != null)
			o.put("client_secret", secret);
		o.put("registration_access_token", registrationToken);
		o.put("registration_client_uri", "https://"+cfg.getHostName()+":"+cfg.getStandardPort()+"/register?client_id="+URLEncoder.encode(fm.getPublicId(), "UTF-8"));
		o.put("client_secret_expires_at", 0);
		o.put("client_id", fm.getOpenidClientId());
		o.put("client_name", fm.getName());
		JSONArray a = new JSONArray();
		if (fm.getOpenidUrl() != null)
			for (String url: fm.getOpenidUrl())
				a.put(url);
		o.put("redirect_uris", a);
		o.put("frontchannel_logout_uri", fm.getOpenidLogoutUrlFront());
		o.put("backchannel_logout_uri", fm.getOpenidLogoutUrlBack());
		return o;
	}

	private void fillList(List<String> l, Object uris) {
		int i;
		if (uris != null) {
			if (uris instanceof String)
				l.add((String)uris);
			if (uris instanceof JSONArray) {
				JSONArray a = (JSONArray) uris;
				for (i = 0; i < a.length(); i++)
					l.add(a.getString(i));
			}
		}
	}

	private String generateRandom() {
		byte b[] = new byte[36];
		new SecureRandom().nextBytes(b);
		return Base64.encodeBytes(b);
	}

	private void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", "Unexpected error");
			o.put("error_description", string);
		} catch (JSONException e) {
			throw new ServletException("Error generating error message "+string, e);
		}
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.addHeader("WWW-Authenticate", "error=\"unexpected_error\",error_description=\""+string+"\"");
		resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
		ServletOutputStream out = resp.getOutputStream();
		out.print( o.toString() );
		out.close();
	}

	private void buildResponse (HttpServletResponse resp, JSONArray o) throws IOException {
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(200);
		ServletOutputStream out = resp.getOutputStream();
		out.print( o.toString() );
		out.close();
	}
}
