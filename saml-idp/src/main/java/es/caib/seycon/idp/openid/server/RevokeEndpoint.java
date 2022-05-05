package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

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

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.client.PasswordManager;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.ui.Messages;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

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
		
		TokenHandler th = TokenHandler.instance();
		try {
			TokenInfo t = null;
			if ("refresh_token".equals(token_type_hint)) {
				t = th.getRefreshToken(token);
			} else {
				t = th.getToken(token);
			}
			
			if ( t != null) {
				FederationMember sp = t.getRequest().getFederationMember();
				Password pass = Password.decode(sp.getOpenidSecret());
				String expectedAuth = sp.getOpenidClientId()+":"+pass.getPassword();

				expectedAuth = "Basic "+Base64.encodeBytes( expectedAuth.getBytes("UTF-8"), Base64.DONT_BREAK_LINES );
				if (! expectedAuth.equals(authentication))
				{
					buildError (resp, "unauthorized_client", "Wrong client credentials", t);
					return;
				}
				
				th.revoke(t);
			}			
			resp.getOutputStream().close();
		} catch (Exception e) {
			buildError (resp, e.toString());
		}
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
	}

	@Override
	protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.addHeader("Access-Control-Allow-Origin", "*");
		resp.addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
		resp.addHeader("Access-Control-Max-Age", "1728000");
		super.service(req, resp);
	}
}
