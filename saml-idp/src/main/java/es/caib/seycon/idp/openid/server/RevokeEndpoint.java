package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.api.Digest;
import com.soffid.iam.addons.federation.common.FederationMember;

public class RevokeEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
	{
		String token_type_hint = req.getParameter("token_type_hint");
		String token = req.getParameter("token");
		String authentication = req.getHeader("Authorization");
		String clientId = req.getParameter("client_id");
		String clientSecret = req.getParameter("client_secret");
		
		TokenHandler th = TokenHandler.instance();
		try {
			if (OidcDebugController.isDebug()) {
				log.info("Received revoke token request");
				log.info("toket_type_hint = "+token_type_hint);
				log.info("token           = "+token);
				log.info("authentication  = "+OidcDebugController.ofuscate(authentication));
				log.info("client_id       = "+clientId);
				log.info("client_secret   = "+OidcDebugController.ofuscate(clientSecret));
			}
			TokenInfo t = null;
			if ("refresh_token".equals(token_type_hint)) {
				t = th.getRefreshToken(token);
			} else {
				t = th.getToken(token);
			}
			
			if ( t != null) {
				FederationMember sp = t.getRequest().getFederationMember();
				Digest pass = sp.getOpenidSecret();
				
				if (pass == null) {
					if (!clientId.equals(t.getRequest().getFederationMember().getOpenidClientId())) {
						buildError(resp, "unauthorized_client", "Wrong client credentials", t);
						return;
					}
				} 
				else if (clientId != null && clientSecret != null) {
					if (!clientId.equals(t.getRequest().getFederationMember().getOpenidClientId()) ||
						!pass.validate(clientSecret)) {
						buildError(resp, "unauthorized_client", "Wrong client credentials", t);
						return;
					}
				} else {
					if (! validAuthentication (authentication, t.getRequest().getFederationMember())) {
						buildError(resp, "unauthorized_client", "Wrong client credentials", t);
						return;
					}

				}

				th.revoke(getServletContext(), req, t);
			}		
			resp.getOutputStream().close();
		} catch (Exception e) {
			buildError (resp, e.toString());
		}
	}

	private boolean validAuthentication(String authentication, FederationMember federationMember) {
		if (!authentication.toLowerCase().startsWith("basic "))
			return false;
		
		String rest = new String (java.util.Base64.getDecoder().decode(authentication.substring(6)), StandardCharsets.UTF_8);
		
		if ( ! rest.startsWith(federationMember.getOpenidClientId()+":"))
			return false;
		
		rest = rest.substring(federationMember.getOpenidClientId().length()+1);
		
		return federationMember.getOpenidSecret().validate(rest);
	}

	private void buildError(HttpServletResponse resp, String string) throws IOException, ServletException {
		buildError(resp, "server_error", string, null);
	}

	private void buildError(HttpServletResponse resp, String string, TokenInfo ti) throws IOException, ServletException {
		buildError(resp, "server_error", string, ti);
	}

	private void buildError(HttpServletResponse resp, String error, String description) throws IOException, ServletException {
		buildError(resp, error, description, null);
	}

	private void buildError(HttpServletResponse resp, String error, String description, TokenInfo ti) throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", error);
			o.put("error_description", description);
			if (ti != null && ti.request != null && ti.request.state != null)
				o.put("state", ti.request.state);
		} catch (JSONException e) {
			throw new ServletException("Error generating error message "+description, e);
		}
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(400);
		ServletOutputStream out = resp.getOutputStream();
		out.print( o.toString() );
		out.close();
		if (OidcDebugController.isDebug()) {
			log.info("Sending back error "+error+": "+description);
		}
	}

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}
}
