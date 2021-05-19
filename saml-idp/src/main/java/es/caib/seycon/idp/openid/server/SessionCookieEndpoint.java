package es.caib.seycon.idp.openid.server;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.api.Session;

import es.caib.seycon.idp.server.Autenticator;

public class SessionCookieEndpoint extends HttpServlet {


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

		String authentication = req.getHeader("Authorization");
		if (authentication == null || ! authentication.toLowerCase().startsWith("bearer "))
		{
			resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
			return;
		}
		String token = authentication.substring(7);
		TokenHandler h = TokenHandler.instance();

		Autenticator autenticator = new Autenticator();
		Session session;
		TokenInfo t = null;
		try {
			t = h.getToken(token);
			if ( t == null)
			{
				resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
				resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
				return;
			}
			session = autenticator.generateOpenidSession(req.getSession(), t.getUser(),
					t.getAuthenticationMethod() == null ? "P": t.getAuthenticationMethod(),
					false);
			Cookie cookie = autenticator.getSessionCookie(t, session);
			h.setSession(t, session);
			JSONObject o = new JSONObject();
			o.put ("user", t.getUser());
			o.put("cookie_name", cookie.getName());
			o.put("cookie_value", cookie.getValue());
			o.put("cookie_domain", cookie.getDomain());
			buildResponse(resp, o);
		} catch (Exception e) {
			log.info("Error generating session cookie", e);
			buildError(resp, e.getClass().getSimpleName(), e.getMessage(), t);
		}
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
}
