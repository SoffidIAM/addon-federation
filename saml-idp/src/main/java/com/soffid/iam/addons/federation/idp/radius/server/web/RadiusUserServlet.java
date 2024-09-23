package com.soffid.iam.addons.federation.idp.radius.server.web;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.idp.radius.packet.RadiusPacket;
import com.soffid.iam.addons.federation.idp.radius.server.CertificateCache;
import com.soffid.iam.addons.federation.idp.radius.server.RadiusServer;
import com.soffid.iam.api.Password;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.ng.exception.InternalErrorException;

public class RadiusUserServlet extends HttpServlet {
	Log log = LogFactory.getLog(getClass());
	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		try {
			String user = req.getPathInfo().substring(1);
			String p = getUserPassword(user);
			ServletInputStream in = req.getInputStream();
			JSONObject o = new JSONObject(new JSONTokener(in));
			log.info("Path "+req.getPathInfo());
			log.info("Received "+o);
			JSONObject r = new JSONObject();
			JSONObject att0 = new JSONObject();
			att0.put("is_json", false);
			att0.put("do_xlat", false);
			att0.put("op", ":=");
			att0.put("value", new JSONArray(new String[] {p}));
			r.put("control:Cleartext-Password", att0);


			RadiusServer s = (RadiusServer) getServletContext().getAttribute("radiusServer");
			CertificateCache certCache = s.getCertificateCache();
			final X509Certificate[] certs = (X509Certificate[])req.getAttribute("javax.servlet.request.X509Certificate");
			if (certs == null || certs.length == 0) {
				resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
			FederationMember federationMember = certCache.getFederationMember(certs[0]);
			if (federationMember == null) {
				resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
			Map<String, Object> attributes = s.generateAttributes(user, federationMember);
			for (String attName: attributes.keySet()) {
				Object value = attributes.get(attName);
				JSONObject att = new JSONObject();
				r.put("request:"+attName, att);
				att.put("is_json", false);
				att.put("do_xlat", false);
				att.put("op", ":=");
				JSONArray values = new JSONArray();
				att.put("value", values);
				try {
					if (value instanceof List) {
						for (Object vv: (List) value)
							values.put(vv.toString());
					}
					else
						values.put(value.toString());
				} catch (NumberFormatException e) {
					log.warn("Cannot parse attribute id "+att, e);
				}
			}

			resp.setContentType("application/json");
			resp.getOutputStream().write(r.toString().getBytes("UTF-8"));
			resp.setStatus(200);
		} catch (Exception e) {
			JSONObject o = new JSONObject();
			o.put("error", e.toString());
			resp.getOutputStream().write(o.toString().getBytes("UTF-8"));
			resp.setStatus(500);
		}
		
	}

	private String getUserPassword(String userName) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		String system = IdpConfig.getConfig().getSystem().getName();
		Password pass = new RemoteServiceLocator().getServerService().getAccountPassword(userName, system);
		if (pass == null)
			return null;
		else
			return pass.getPassword();
	}

}
