package es.caib.seycon.idp.openid.server;

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
        	SAMLProfile openIdProfile = useOpenidProfile();
			Map<String, Object> att = new HashMap<String, Object>();
			att.put("issuer", "https://"+c.getHostName()+":"+c.getStandardPort());
			att.put("authorization_endpoint", "https://"+c.getHostName()+":"+c.getStandardPort()+openIdProfile.getAuthorizationEndpoint());
			att.put("token_endpoint", "https://"+c.getHostName()+":"+c.getStandardPort()+openIdProfile.getTokenEndpoint());
			att.put("userinfo_endpoint", "https://"+c.getHostName()+":"+c.getStandardPort()+openIdProfile.getUserInfoEndpoint());
			if (openIdProfile.getRevokeEndpoint() != null)
				att.put("revoke_endpoint", "https://"+c.getHostName()+":"+c.getStandardPort()+openIdProfile.getRevokeEndpoint());
			att.put("jwks_uri", "https://"+c.getHostName()+":"+c.getStandardPort()+"/.well-known/jwks.json");
			JSONArray scopes = new JSONArray();
			scopes.put("openid");
			att.put("scopes_supported", scopes);
			JSONArray rt = new JSONArray();
			rt.put("code");
			rt.put("token");
			rt.put("id_token");
			att.put("response_types_supported", rt);

			JSONArray at = new JSONArray();
			at.put("client_secret_basic");
			at.put("client_secret_post");
			att.put("token_endpoint_auth_methods_supported", at);
			
			JSONArray st = new JSONArray();
			st.put("public");
			st.put("pairwise");
			att.put("subject_types_supported", st);
			
			JSONArray sa = new JSONArray();
			sa.put("RS256");
			att.put("id_token_signing_alg_values_supported", sa);
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

}
