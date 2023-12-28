package es.caib.seycon.idp.sse.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

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

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.service.FederationService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.ui.IframeSession;
import es.caib.seycon.ng.exception.InternalErrorException;

public class ConfigurationEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		doPost(req, resp);
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");


        try {
        	IdpConfig c = IdpConfig.getConfig();
        	String pathInfo = req.getPathInfo();
        	if (pathInfo != null) {
        		String issuerName = pathInfo.substring(1);
        		if (!issuerName.equals(c.getFederationMember().getHostName())) {
        			resp.setStatus(HttpServletResponse.SC_NOT_FOUND);
        			return;
        		}
        	}
			Map<String, Object> att = new HashMap<String, Object>();
			final String portSuffix = c.getStandardPort() == 443 ? "":  ":"+c.getStandardPort();
			att.put("issuer", "https://"+c.getFederationMember().getHostName()+portSuffix);
			att.put("jwks_uri", "https://"+c.getFederationMember().getHostName()+portSuffix+"/.well-known/jwks.json");
			att.put("delivery_methods_supported", new JSONArray(new String[] {
					"https://schemas.openid.net/secevent/risc/delivery-method/push",
					"https://schemas.openid.net/secevent/risc/delivery-method/poll"
			}));
			att.put("configuration_endpoint", "https://"+c.getFederationMember().getHostName()+portSuffix+"/sse/stream");
			att.put("status_endpoint", "https://"+c.getFederationMember().getHostName()+portSuffix+"/sse/status");
			att.put("add_subject_endpoint", "https://"+c.getFederationMember().getHostName()+portSuffix+"/sse/subject-add");
			att.put("remove_subject_endpoint", "https://"+c.getFederationMember().getHostName()+portSuffix+"/sse/subject-remove");
			att.put("verification_endpoint", "https://"+c.getFederationMember().getHostName()+portSuffix+"/sse/verification");
			att.put("critical_subject_members", new JSONArray(new String[] { "user" }));
			JSONObject o = new JSONObject( att );
			buildResponse(resp, o);
		} catch (InternalErrorException e) {
			log.warn("Error evaluating claims", e);
			buildError(resp, "Error resolving attributes");
			return;
		} catch (Throwable e) {
			log.warn("Error generating open id token", e);
			buildError(resp, "Error generating open id token");
			return;
		}
	}

	private void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", string);
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

	private void buildResponse (HttpServletResponse resp, JSONObject o) throws IOException {
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(200);
		ServletOutputStream out = resp.getOutputStream();
		out.print( o.toString() );
		out.close();
	}
	
	private SAMLProfile useOpenidProfile() throws InternalErrorException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException {
        IdpConfig c = IdpConfig.getConfig();
		FederationService federacioService = c.getFederationService();
		FederationMember fm = c.getFederationMember();
		
        Collection<SAMLProfile> profiles = federacioService
                .findProfilesByFederationMember(fm);
        for (Iterator<SAMLProfile> it = profiles.iterator(); it.hasNext();) {
            SAMLProfile profile = (SAMLProfile) it.next();
            SamlProfileEnumeration type = profile.getClasse();
            if (type.equals(SamlProfileEnumeration.OPENID)) {
            	return profile;
            }
        }
        return null;
	}

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}
}