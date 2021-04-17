package es.caib.seycon.idp.openid.server;

import java.io.IOException;
import java.net.HttpCookie;
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
import com.soffid.iam.api.Password;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.impersonation.ImpersonationHandler;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class ImpersonationEndpoint extends HttpServlet {

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
		TokenInfo t = null;
			
		try {
			t = h.getToken(token);
			if ( t == null)
			{
				resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
				resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
				return;
			}
			String url = req.getParameter("url");
			FederationMember fm = t.getRequest().getFederationMember();
			if (!fm.getImpersonations().contains(url)) {
				resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
				resp.addHeader("WWW-Authenticate", "Bearer realm=openid");
				return;
			}
			impersonate (fm, url, t, resp);
		} catch (Throwable e) {
			log.warn("Error impersonating session", e);
			buildError(resp, "Error impersonating session");
		}
	}

	private void impersonate(FederationMember fm, String url, TokenInfo t, HttpServletResponse resp) throws Exception {
		ImpersonationHandler h = new ImpersonationHandler();
		h.impersonate(getServletContext(), url, t);
		JSONArray a = new JSONArray();
		for (HttpCookie cookie: h.getServerCookies()) {
			JSONObject o = new JSONObject();
			o.put("name", cookie.getName());
			o.put("value", cookie.getValue());
			o.put("domain", cookie.getDomain());
			o.put("path", cookie.getPath());
			a.put(o);
		}
		buildResponse(resp, a);
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
