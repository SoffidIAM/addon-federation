package es.caib.seycon.idp.openid.server;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.api.Password;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.util.Base64;

public class TokenIntrospectionEndpoint extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	Log log = LogFactory.getLog(getClass());

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String tokenId = req.getParameter("token");
		String authentication = req.getHeader("Authorization");
		try {
			IdpConfig config = IdpConfig.getConfig();

			TokenHandler h = TokenHandler.instance();

			if (authentication != null && authentication.toLowerCase().startsWith("basic ")) {
				String decoded = new String(Base64.decode(authentication.substring(6)), "UTF-8");
				String clientId2 = decoded.substring(0, decoded.indexOf(":"));
				FederationMember fm = config.getFederationService().findFederationMemberByClientID(clientId2);
				Password pass = Password.decode(fm.getOpenidSecret());
				String expectedAuth = fm.getOpenidClientId() + ":" + pass.getPassword();

				expectedAuth = "Basic " + Base64.encodeBytes(expectedAuth.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
				if (!expectedAuth.equals(authentication)) {
					buildError(resp, "unauthorized_client", "Wrong client credentials", null);
					return;
				}
				TokenInfo t = h.getToken(tokenId);
				JSONObject o = new JSONObject();
				if (t == null || t.isExpired())
					o.put("active",  false);
				else {
					o.put("active", true);
					o.put("scope", t.getRequest().getScope() == null ? "openid": t.getRequest().getScope());
					o.put("client_id", t.getRequest().getClientId());
					o.put("username", t.getUser());
					o.put("exp", t.getExpires());
				}
				buildResponse(resp, o);
			} else {
				resp.setHeader("WWW-Authenticate", "Basic realm=\"Client credentials\"");
				resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
		} catch (Throwable e) {
			log.warn("Error reading access token", e);
			buildError(resp, "Error reading access token", null);
			return;
		}
	}

	private void buildError(HttpServletResponse resp, String string, TokenInfo ti)
			throws IOException, ServletException {
		buildError(resp, "server_error", string, ti);
	}

	private void buildError(HttpServletResponse resp, String error, String description, TokenInfo ti)
			throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", error);
			o.put("error_description", description);
			if (ti != null && ti.request != null && ti.request.state != null)
				o.put("state", ti.request.state);
		} catch (JSONException e) {
			throw new ServletException("Error generating error message " + description, e);
		}
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(400);
		ServletOutputStream out = resp.getOutputStream();
		out.print(o.toString());
		out.close();
	}

	private void buildResponse(HttpServletResponse resp, JSONObject o) throws IOException {
		resp.setContentType("application/json");
		resp.addHeader("Cache-control", "no-store");
		resp.addHeader("Pragma", "no-cache");
		resp.setStatus(200);
		ServletOutputStream out = resp.getOutputStream();
		out.print(o.toString());
		out.close();
	}

}
