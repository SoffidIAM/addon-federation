package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.json.JSONObject;

import com.soffid.iam.addons.federation.common.FederationMember;

import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.textformatter.TextFormatException;

public class KeepAliveServlet extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String URI = "/keepalive"; //$NON-NLS-1$
	Log log = LogFactory.getLog(getClass());
	
    void process (HttpServletRequest req, HttpServletResponse resp) throws UnsupportedEncodingException, IOException, ServletException {
    	boolean ok = false;
    	String user = null;
    	try {
			HttpSession s = req.getSession(false);
			if (s != null) {
				AuthenticationContext authCtx = AuthenticationContext.fromRequest(req);
				if (authCtx != null) { 
					ok = authCtx.isFinished();
					user = authCtx.getUser();
				}
			}
			JSONObject o = new JSONObject();
			o.put("valid", ok);
			o.put("user", user);
			buildResponse(resp, o);
    	} catch (Exception e) {
    		log.warn("Error processing keepalive session", e);
    		buildError (resp, "Unexpected error", e.toString());
    	}
    }

	private void buildError(HttpServletResponse resp, String error, String description)
			throws IOException, ServletException {
		JSONObject o = new JSONObject();
		try {
			o.put("error", error);
			o.put("error_description", description);
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


    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        process (req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        process (req, resp);
    }

}
